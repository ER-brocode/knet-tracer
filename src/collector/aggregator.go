package collector

import (
	"sync"
	"time"

	"github.com/ER-brocode/knet-tracer/src/types"
)

// FlowStats aggregates metrics for a specific 5-tuple TCP connection
type FlowStats struct {
	Key             types.FlowKey
	Comm            string
	PID             uint32
	TGID            uint32
	SRTTMicros      uint64
	MinRTTMicros    uint64
	MaxRTTMicros    uint64
	RTTVarMicros    uint64
	SampleCount     uint64
	TotalRetrans    uint64
	BytesAcked      uint64
	BytesRcvd       uint64
	CWND            uint32
	SSTHRESH        uint32
	RcvBufBytes     uint32
	SndBufBytes     uint32
	TCPState        uint8
	PacketDrops     uint64
	LastDropReason  types.DropReason
	LastDropAddress uint64
	LastUpdated     time.Time
}

// FlowAggregator maintains real-time aggregated metrics per network flow.
type FlowAggregator struct {
	mu          sync.RWMutex
	flows       map[string]*FlowStats
	ttlDuration time.Duration
}

// NewFlowAggregator creates a new thread-safe flow aggregator.
func NewFlowAggregator(ttl time.Duration) *FlowAggregator {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &FlowAggregator{
		flows:       make(map[string]*FlowStats),
		ttlDuration: ttl,
	}
}

// flowKeyString returns a unique map key for a 5-tuple.
func flowKeyString(key types.FlowKey) string {
	return key.SrcIP + ":" + uint16ToStr(key.SrcPort) + "->" + key.DstIP + ":" + uint16ToStr(key.DstPort) + "[" + key.Proto + "]"
}

func uint16ToStr(v uint16) string {
	return string([]byte{
		byte('0' + (v/10000)%10),
		byte('0' + (v/1000)%10),
		byte('0' + (v/100)%10),
		byte('0' + (v/10)%10),
		byte('0' + v%10),
	})
}

// RecordTCPRTT processes a TCP RTT sample event and updates running latency statistics.
func (a *FlowAggregator) RecordTCPRTT(evt types.TCPRTTEvent) {
	key := types.FlowKey{
		SrcIP:   types.FormatIP(evt.SAddr),
		DstIP:   types.FormatIP(evt.DAddr),
		SrcPort: evt.SPort,
		DstPort: evt.DPort,
		Proto:   "TCP",
	}
	k := flowKeyString(key)

	a.mu.Lock()
	defer a.mu.Unlock()

	stat, exists := a.flows[k]
	if !exists {
		stat = &FlowStats{
			Key:          key,
			PID:          evt.PID,
			TGID:         evt.TGID,
			Comm:         string(evt.Comm[:]),
			MinRTTMicros: uint64(evt.MinRTT),
			MaxRTTMicros: uint64(evt.SRTT),
		}
		a.flows[k] = stat
	}

	srtt := uint64(evt.SRTT)
	stat.SRTTMicros = srtt
	stat.RTTVarMicros = uint64(evt.RTTVar)
	if srtt < stat.MinRTTMicros || stat.MinRTTMicros == 0 {
		stat.MinRTTMicros = srtt
	}
	if srtt > stat.MaxRTTMicros {
		stat.MaxRTTMicros = srtt
	}
	stat.SampleCount++
	stat.TotalRetrans = uint64(evt.TotalRetr)
	stat.LastUpdated = time.Now()
}

// RecordPacketDrop processes a kernel skb drop event.
func (a *FlowAggregator) RecordPacketDrop(evt types.PacketDropEvent) {
	key := types.FlowKey{
		SrcIP:   types.FormatIP(evt.SAddr),
		DstIP:   types.FormatIP(evt.DAddr),
		SrcPort: evt.SPort,
		DstPort: evt.DPort,
		Proto:   "TCP",
	}
	if evt.Protocol == 17 {
		key.Proto = "UDP"
	}
	k := flowKeyString(key)

	a.mu.Lock()
	defer a.mu.Unlock()

	stat, exists := a.flows[k]
	if !exists {
		stat = &FlowStats{
			Key:  key,
			Comm: string(evt.Comm[:]),
		}
		a.flows[k] = stat
	}

	stat.PacketDrops++
	stat.LastDropReason = evt.Reason
	stat.LastDropAddress = evt.Location
	stat.LastUpdated = time.Now()
}

// RecordSocketStats processes socket congestion and buffer health telemetry.
func (a *FlowAggregator) RecordSocketStats(evt types.SocketStatsEvent) {
	key := types.FlowKey{
		SrcIP:   types.FormatIP(evt.SAddr),
		DstIP:   types.FormatIP(evt.DAddr),
		SrcPort: evt.SPort,
		DstPort: evt.DPort,
		Proto:   "TCP",
	}
	k := flowKeyString(key)

	a.mu.Lock()
	defer a.mu.Unlock()

	stat, exists := a.flows[k]
	if !exists {
		stat = &FlowStats{
			Key: key,
		}
		a.flows[k] = stat
	}

	stat.BytesAcked = evt.BytesAcked
	stat.BytesRcvd = evt.BytesRcvd
	stat.CWND = evt.CWND
	stat.SSTHRESH = evt.SSTHRESH
	stat.TotalRetrans = uint64(evt.PktRetrans)
	stat.RcvBufBytes = evt.RcvBufBytes
	stat.SndBufBytes = evt.SndBufBytes
	stat.TCPState = evt.TCPState
	stat.LastUpdated = time.Now()
}

// Snapshot returns a copy of current active flows.
func (a *FlowAggregator) Snapshot() []FlowStats {
	a.mu.RLock()
	defer a.mu.RUnlock()

	res := make([]FlowStats, 0, len(a.flows))
	for _, v := range a.flows {
		res = append(res, *v)
	}
	return res
}

// PruneExpired evicts connections idle past TTL.
func (a *FlowAggregator) PruneExpired() int {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	evicted := 0
	for k, stat := range a.flows {
		if now.Sub(stat.LastUpdated) > a.ttlDuration {
			delete(a.flows, k)
			evicted++
		}
	}
	return evicted
}

// FlowCount returns the active flow count.
func (a *FlowAggregator) FlowCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.flows)
}
