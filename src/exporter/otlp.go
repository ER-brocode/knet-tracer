package exporter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/ER-brocode/knet-tracer/src/collector"
)

// OTLPConfig holds parameters for sending metrics to OpenTelemetry Collector
type OTLPConfig struct {
	Endpoint      string        // e.g. "http://localhost:4318/v1/metrics"
	ExportInterval time.Duration // default 5 seconds
	ServiceName   string
	Headers       map[string]string
}

// OTLPExporter serializes aggregated kernel telemetry and pushes to an OpenTelemetry collector.
type OTLPExporter struct {
	config     OTLPConfig
	aggregator *collector.FlowAggregator
	client     *http.Client
	stopCh     chan struct{}
}

// NewOTLPExporter creates a new OTLP exporter instance.
func NewOTLPExporter(cfg OTLPConfig, agg *collector.FlowAggregator) *OTLPExporter {
	if cfg.ExportInterval <= 0 {
		cfg.ExportInterval = 5 * time.Second
	}
	if cfg.ServiceName == "" {
		cfg.ServiceName = "knet-tracer"
	}
	return &OTLPExporter{
		config:     cfg,
		aggregator: agg,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		stopCh: make(chan struct{}),
	}
}

// Start begins periodic metric exportation to the OTLP endpoint.
func (o *OTLPExporter) Start(ctx context.Context) {
	ticker := time.NewTicker(o.config.ExportInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-o.stopCh:
			return
		case <-ticker.C:
			if err := o.exportBatch(ctx); err != nil {
				log.Printf("[knet-otlp] export batch warning: %v", err)
			}
		}
	}
}

// Stop cleanly terminates the exporter.
func (o *OTLPExporter) Stop() {
	close(o.stopCh)
}

// exportBatch formats and sends telemetry data over HTTP POST to OTLP collector.
func (o *OTLPExporter) exportBatch(ctx context.Context) error {
	flows := o.aggregator.Snapshot()
	if len(flows) == 0 {
		return nil
	}

	payload := o.buildOTLPJSON(flows)
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal otlp payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.config.Endpoint, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create http request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	for k, v := range o.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := o.client.Do(req)
	if err != nil {
		return fmt.Errorf("send otlp post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("otlp collector returned non-2xx status: %d", resp.StatusCode)
	}

	return nil
}

// buildOTLPJSON maps internal flows into standard OpenTelemetry Metrics JSON schema.
func (o *OTLPExporter) buildOTLPJSON(flows []collector.FlowStats) map[string]interface{} {
	metricsList := make([]map[string]interface{}, 0, len(flows)*4)
	nowNano := time.Now().UnixNano()

	for _, f := range flows {
		commonAttributes := []map[string]interface{}{
			{"key": "net.peer.name", "value": map[string]string{"stringValue": f.Key.DstIP}},
			{"key": "net.peer.port", "value": map[string]int{"intValue": int(f.Key.DstPort)}},
			{"key": "net.host.name", "value": map[string]string{"stringValue": f.Key.SrcIP}},
			{"key": "process.name", "value": map[string]string{"stringValue": f.Comm}},
		}

		// Metric 1: TCP Round-Trip Time Gauge
		if f.SRTTMicros > 0 {
			metricsList = append(metricsList, map[string]interface{}{
				"name":        "network.tcp.rtt",
				"description": "Kernel TCP smoothed round-trip time in microseconds",
				"unit":        "us",
				"gauge": map[string]interface{}{
					"dataPoints": []map[string]interface{}{
						{
							"timeUnixNano":   nowNano,
							"asDouble":       float64(f.SRTTMicros),
							"attributes":     commonAttributes,
						},
					},
				},
			})
		}

		// Metric 2: Packet Drops Sum
		if f.PacketDrops > 0 {
			dropAttrs := append(commonAttributes, map[string]interface{}{
				"key": "drop.reason", "value": map[string]string{"stringValue": f.LastDropReason.String()},
			})
			metricsList = append(metricsList, map[string]interface{}{
				"name":        "network.packet.drops",
				"description": "Kernel packet drop count categorized by drop reason",
				"unit":        "{drops}",
				"sum": map[string]interface{}{
					"dataPoints": []map[string]interface{}{
						{
							"timeUnixNano":   nowNano,
							"asInt":          int64(f.PacketDrops),
							"attributes":     dropAttrs,
						},
					},
					"aggregationTemporality": 2, // Cumulative
					"isMonotonic":            true,
				},
			})
		}
	}

	return map[string]interface{}{
		"resourceMetrics": []map[string]interface{}{
			{
				"resource": map[string]interface{}{
					"attributes": []map[string]interface{}{
						{"key": "service.name", "value": map[string]string{"stringValue": o.config.ServiceName}},
						{"key": "telemetry.sdk.name", "value": map[string]string{"stringValue": "knet-tracer"}},
					},
				},
				"scopeMetrics": []map[string]interface{}{
					{
						"scope": map[string]string{
							"name":    "knet-tracer/collector",
							"version": "1.0.0",
						},
						"metrics": metricsList,
					},
				},
			},
		},
	}
}
