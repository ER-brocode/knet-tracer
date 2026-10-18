package exporter

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/ER-brocode/knet-tracer/src/collector"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// PrometheusExporter exposes network metrics in standard Prometheus exposition format.
type PrometheusExporter struct {
	aggregator *collector.FlowAggregator
	server     *http.Server
	listenAddr string

	rttHistogram   *prometheus.HistogramVec
	dropCounter    *prometheus.CounterVec
	cwndGauge      *prometheus.GaugeVec
	retransCounter *prometheus.CounterVec
	bytesTotal     *prometheus.CounterVec
	activeFlows    prometheus.Gauge
}

// NewPrometheusExporter constructs a Prometheus telemetry exporter.
func NewPrometheusExporter(agg *collector.FlowAggregator, listenAddr string) *PrometheusExporter {
	exp := &PrometheusExporter{
		aggregator: agg,
		listenAddr: listenAddr,
		rttHistogram: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "knet",
				Subsystem: "tcp",
				Name:      "rtt_microseconds",
				Help:      "Kernel-measured TCP Round Trip Time in microseconds",
				Buckets:   []float64{100, 250, 500, 1000, 2500, 5000, 10000, 25000, 50000, 100000, 250000},
			},
			[]string{"src_ip", "dst_ip", "dst_port", "comm"},
		),
		dropCounter: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "knet",
				Subsystem: "packet",
				Name:      "drops_total",
				Help:      "Total count of skb drops categorized by kernel drop reason",
			},
			[]string{"src_ip", "dst_ip", "reason", "proto"},
		),
		cwndGauge: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "knet",
				Subsystem: "tcp",
				Name:      "congestion_window_segments",
				Help:      "TCP congestion window size (snd_cwnd) in segments",
			},
			[]string{"src_ip", "dst_ip", "dst_port"},
		),
		retransCounter: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "knet",
				Subsystem: "tcp",
				Name:      "retransmissions_total",
				Help:      "Cumulative count of retransmitted segments",
			},
			[]string{"src_ip", "dst_ip", "dst_port"},
		),
		bytesTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "knet",
				Subsystem: "flow",
				Name:      "bytes_acked_total",
				Help:      "Total bytes successfully acknowledged across TCP flow",
			},
			[]string{"src_ip", "dst_ip", "dst_port"},
		),
		activeFlows: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: "knet",
				Subsystem: "engine",
				Name:      "active_tracked_flows",
				Help:      "Number of actively tracked kernel network flows",
			},
		),
	}

	prometheus.MustRegister(
		exp.rttHistogram,
		exp.dropCounter,
		exp.cwndGauge,
		exp.retransCounter,
		exp.bytesTotal,
		exp.activeFlows,
	)

	return exp
}

// SyncMetrics scrapes the aggregator and updates Prometheus collector states.
func (e *PrometheusExporter) SyncMetrics() {
	flows := e.aggregator.Snapshot()
	e.activeFlows.Set(float64(len(flows)))

	for _, f := range flows {
		dstPortStr := fmt.Sprintf("%d", f.Key.DstPort)

		if f.SRTTMicros > 0 {
			e.rttHistogram.WithLabelValues(f.Key.SrcIP, f.Key.DstIP, dstPortStr, f.Comm).
				Observe(float64(f.SRTTMicros))
		}
		if f.PacketDrops > 0 {
			e.dropCounter.WithLabelValues(f.Key.SrcIP, f.Key.DstIP, f.LastDropReason.String(), f.Key.Proto).
				Add(float64(f.PacketDrops))
		}
		e.cwndGauge.WithLabelValues(f.Key.SrcIP, f.Key.DstIP, dstPortStr).
			Set(float64(f.CWND))
		e.retransCounter.WithLabelValues(f.Key.SrcIP, f.Key.DstIP, dstPortStr).
			Add(float64(f.TotalRetrans))
		e.bytesTotal.WithLabelValues(f.Key.SrcIP, f.Key.DstIP, dstPortStr).
			Add(float64(f.BytesAcked))
	}
}

// Start launches the HTTP server for /metrics scraping.
func (e *PrometheusExporter) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"UP","engine":"knet-tracer"}`))
	})

	e.server = &http.Server{
		Addr:         e.listenAddr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// Background ticker for metrics synchronization
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				e.SyncMetrics()
			}
		}
	}()

	return e.server.ListenAndServe()
}

// Shutdown gracefully terminates the HTTP server.
func (e *PrometheusExporter) Shutdown(ctx context.Context) error {
	if e.server != nil {
		return e.server.Shutdown(ctx)
	}
	return nil
}
