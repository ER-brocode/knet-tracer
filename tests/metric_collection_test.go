package tests

import (
	"context"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/ER-brocode/knet-tracer/src/collector"
	"github.com/ER-brocode/knet-tracer/src/exporter"
	"github.com/ER-brocode/knet-tracer/src/types"
)

func binaryIP(a, b, c, d byte) uint32 {
	return uint32(a) | uint32(b)<<8 | uint32(c)<<16 | uint32(d)<<24
}

// TestMetricAggregationPipeline validates ingestion and statistical rollup across multiple flows
func TestMetricAggregationPipeline(t *testing.T) {
	agg := collector.NewFlowAggregator(10 * time.Minute)
	consumer := collector.NewConsumer(agg)

	// Simulate 100 TCP RTT events across 5 distinct target IPs
	srcIP := binaryIP(192, 168, 1, 10)
	dstIPs := []uint32{
		binaryIP(10, 0, 0, 1),
		binaryIP(10, 0, 0, 2),
		binaryIP(10, 0, 0, 3),
		binaryIP(10, 0, 0, 4),
		binaryIP(10, 0, 0, 5),
	}

	for i := 0; i < 100; i++ {
		target := dstIPs[i%len(dstIPs)]
		var comm [16]byte
		copy(comm[:], []byte("microservice"))

		consumer.IngestTCPRTT(types.TCPRTTEvent{
			SAddr:     srcIP,
			DAddr:     target,
			SPort:     uint16(40000 + (i % 10)),
			DPort:     443,
			PID:       1234,
			TGID:      1234,
			SRTT:      uint32(1000 + (i * 20)),
			RTTVar:    150,
			MinRTT:    850,
			TotalRetr: uint32(i / 20),
			Comm:      comm,
			Timestamp: uint64(time.Now().UnixNano()),
		})
	}

	// Verify aggregator holds tracked flows
	flows := agg.Snapshot()
	if len(flows) == 0 {
		t.Fatalf("expected active flows, got 0")
	}

	t.Logf("Successfully verified %d concurrent active network flows", len(flows))

	// Verify values for first flow
	f := flows[0]
	if f.SRTTMicros == 0 {
		t.Errorf("expected non-zero SRTT, got %d", f.SRTTMicros)
	}
	if f.MinRTTMicros == 0 {
		t.Errorf("expected min RTT recorded")
	}
}

// TestPacketDropAccounting validates kernel drop reason categorization
func TestPacketDropAccounting(t *testing.T) {
	agg := collector.NewFlowAggregator(5 * time.Minute)
	consumer := collector.NewConsumer(agg)

	srcIP := binaryIP(10, 1, 1, 5)
	dstIP := binaryIP(172, 20, 0, 100)

	var comm [16]byte
	copy(comm[:], []byte("packet-filter"))

	// Inject 15 drops of type TCPReset and 5 drops of type QueuePurge
	for i := 0; i < 15; i++ {
		consumer.IngestPacketDrop(types.PacketDropEvent{
			SAddr:     srcIP,
			DAddr:     dstIP,
			SPort:     8080,
			DPort:     55000,
			Protocol:  6,
			Reason:    types.DropReasonTCPReset,
			Location:  0xffffffff81800000,
			Comm:      comm,
			Timestamp: uint64(time.Now().UnixNano()),
		})
	}

	for i := 0; i < 5; i++ {
		consumer.IngestPacketDrop(types.PacketDropEvent{
			SAddr:     srcIP,
			DAddr:     dstIP,
			SPort:     8080,
			DPort:     55000,
			Protocol:  6,
			Reason:    types.DropReasonQueuePurge,
			Location:  0xffffffff81801234,
			Comm:      comm,
			Timestamp: uint64(time.Now().UnixNano()),
		})
	}

	flows := agg.Snapshot()
	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}

	if flows[0].PacketDrops != 20 {
		t.Errorf("expected 20 drops, got %d", flows[0].PacketDrops)
	}
	if flows[0].LastDropReason != types.DropReasonQueuePurge {
		t.Errorf("expected last drop reason QueuePurge, got %v", flows[0].LastDropReason)
	}
}

// TestFlowEvictionTTL verifies that expired inactive flows are properly reclaimed
func TestFlowEvictionTTL(t *testing.T) {
	agg := collector.NewFlowAggregator(10 * time.Millisecond)
	consumer := collector.NewConsumer(agg)

	consumer.IngestTCPRTT(types.TCPRTTEvent{
		SAddr: binaryIP(127, 0, 0, 1),
		DAddr: binaryIP(127, 0, 0, 1),
		SPort: 1111,
		DPort: 2222,
		SRTT:  300,
	})

	if agg.FlowCount() != 1 {
		t.Fatalf("expected 1 flow before eviction, got %d", agg.FlowCount())
	}

	// Sleep past TTL
	time.Sleep(30 * time.Millisecond)
	evicted := agg.PruneExpired()
	if evicted != 1 {
		t.Errorf("expected 1 evicted flow, got %d", evicted)
	}
	if agg.FlowCount() != 0 {
		t.Errorf("expected 0 remaining flows, got %d", agg.FlowCount())
	}
}

// TestOTLPExporterIntegration tests JSON serialization and HTTP transport against mock OTLP server
func TestOTLPExporterIntegration(t *testing.T) {
	receivedRequests := 0
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		receivedRequests++
		mu.Unlock()
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"partialSuccess":{}}`))
	}))
	defer server.Close()

	agg := collector.NewFlowAggregator(5 * time.Minute)
	agg.RecordTCPRTT(types.TCPRTTEvent{
		SAddr:  binaryIP(192, 168, 1, 50),
		DAddr:  binaryIP(10, 0, 0, 1),
		SPort:  9000,
		DPort:  443,
		SRTT:   1200,
		MinRTT: 1100,
	})

	otlp := exporter.NewOTLPExporter(exporter.OTLPConfig{
		Endpoint:       server.URL,
		ExportInterval: 50 * time.Millisecond,
		ServiceName:    "knet-test-suite",
	}, agg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go otlp.Start(ctx)

	// Wait for at least one batch export
	time.Sleep(150 * time.Millisecond)
	otlp.Stop()

	mu.Lock()
	count := receivedRequests
	mu.Unlock()

	if count == 0 {
		t.Errorf("expected OTLP exporter to send at least 1 HTTP request, got %d", count)
	}
}

// TestConcurrentIngestion verifies thread safety under high parallel load
func TestConcurrentIngestion(t *testing.T) {
	agg := collector.NewFlowAggregator(5 * time.Minute)
	consumer := collector.NewConsumer(agg)

	const goroutines = 10
	const iterations = 500
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				consumer.IngestTCPRTT(types.TCPRTTEvent{
					SAddr:  binaryIP(10, 0, byte(workerID), 1),
					DAddr:  binaryIP(10, 0, 0, 254),
					SPort:  uint16(20000 + workerID),
					DPort:  80,
					SRTT:   uint32(200 + rand.Intn(1000)),
					MinRTT: 150,
				})
			}
		}(g)
	}

	wg.Wait()
	readCount, _, _ := consumer.Stats()
	if readCount != uint64(goroutines*iterations) {
		t.Errorf("expected %d events read, got %d", goroutines*iterations, readCount)
	}
	if agg.FlowCount() != goroutines {
		t.Errorf("expected %d flows, got %d", goroutines, agg.FlowCount())
	}
}
