package collector

import (
	"context"
	"fmt"
	"log"
	"sync/atomic"
	"time"

	"github.com/ER-brocode/knet-tracer/src/types"
)

// RingBufferReader defines an interface for reading bytes or events from kernel eBPF ring buffers
type RingBufferReader interface {
	Read(ctx context.Context, handler func([]byte) error) error
	Close() error
}

// Consumer consumes ring buffer records and routes them into the flow aggregator.
type Consumer struct {
	aggregator       *FlowAggregator
	eventsRead       uint64
	eventsDropped    uint64
	bytesRead        uint64
	mockMode         bool
	tcpRTTChannel    chan types.TCPRTTEvent
	packetDropChan   chan types.PacketDropEvent
	socketStatsChan  chan types.SocketStatsEvent
	stopCh           chan struct{}
}

// NewConsumer creates a new ring buffer consumer.
func NewConsumer(agg *FlowAggregator) *Consumer {
	return &Consumer{
		aggregator:      agg,
		tcpRTTChannel:   make(chan types.TCPRTTEvent, 10000),
		packetDropChan:  make(chan types.PacketDropEvent, 10000),
		socketStatsChan: make(chan types.SocketStatsEvent, 10000),
		stopCh:          make(chan struct{}),
	}
}

// IngestTCPRTT sends an RTT event directly to the consumer pipeline.
func (c *Consumer) IngestTCPRTT(evt types.TCPRTTEvent) {
	atomic.AddUint64(&c.eventsRead, 1)
	atomic.AddUint64(&c.bytesRead, uint64(56))
	c.aggregator.RecordTCPRTT(evt)
}

// IngestPacketDrop sends a packet drop event to the consumer pipeline.
func (c *Consumer) IngestPacketDrop(evt types.PacketDropEvent) {
	atomic.AddUint64(&c.eventsRead, 1)
	atomic.AddUint64(&c.bytesRead, uint64(48))
	c.aggregator.RecordPacketDrop(evt)
}

// IngestSocketStats sends a socket stats event to the consumer pipeline.
func (c *Consumer) IngestSocketStats(evt types.SocketStatsEvent) {
	atomic.AddUint64(&c.eventsRead, 1)
	atomic.AddUint64(&c.bytesRead, uint64(56))
	c.aggregator.RecordSocketStats(evt)
}

// Stats returns runtime performance metrics of the consumer.
func (c *Consumer) Stats() (read uint64, dropped uint64, bytes uint64) {
	return atomic.LoadUint64(&c.eventsRead),
		atomic.LoadUint64(&c.eventsDropped),
		atomic.LoadUint64(&c.bytesRead)
}

// StartBackgroundPruner launches periodic pruning of dead TCP flows.
func (c *Consumer) StartBackgroundPruner(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-c.stopCh:
				return
			case <-ticker.C:
				evicted := c.aggregator.PruneExpired()
				if evicted > 0 {
					log.Printf("[knet-collector] evicted %d expired connection flows", evicted)
				}
			}
		}
	}()
}

// Close terminates background routines.
func (c *Consumer) Close() error {
	close(c.stopCh)
	return nil
}

// ParseEventBuffer decodes raw binary ringbuffer payload into strongly typed telemetry events.
func ParseEventBuffer(raw []byte) (interface{}, error) {
	if len(raw) < 1 {
		return nil, fmt.Errorf("buffer too short: %d bytes", len(raw))
	}
	// Binary unpack based on length or prefix
	if len(raw) == 56 {
		// TCP RTT event
		evt := types.TCPRTTEvent{
			SAddr:     uint32(raw[0]) | uint32(raw[1])<<8 | uint32(raw[2])<<16 | uint32(raw[3])<<24,
			DAddr:     uint32(raw[4]) | uint32(raw[5])<<8 | uint32(raw[6])<<16 | uint32(raw[7])<<24,
			SPort:     uint16(raw[8]) | uint16(raw[9])<<8,
			DPort:     uint16(raw[10]) | uint16(raw[11])<<8,
			PID:       uint32(raw[12]) | uint32(raw[13])<<8 | uint32(raw[14])<<16 | uint32(raw[15])<<24,
			TGID:      uint32(raw[16]) | uint32(raw[17])<<8 | uint32(raw[18])<<16 | uint32(raw[19])<<24,
			SRTT:      uint32(raw[20]) | uint32(raw[21])<<8 | uint32(raw[22])<<16 | uint32(raw[23])<<24,
			RTTVar:    uint32(raw[24]) | uint32(raw[25])<<8 | uint32(raw[26])<<16 | uint32(raw[27])<<24,
			MinRTT:    uint32(raw[28]) | uint32(raw[29])<<8 | uint32(raw[30])<<16 | uint32(raw[31])<<24,
			TotalRetr: uint32(raw[32]) | uint32(raw[33])<<8 | uint32(raw[34])<<16 | uint32(raw[35])<<24,
		}
		copy(evt.Comm[:], raw[36:52])
		return evt, nil
	}
	return nil, fmt.Errorf("unknown event payload length %d", len(raw))
}
