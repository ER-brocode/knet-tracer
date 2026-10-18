package types

import "net"

// EventType enumerates telemetry event classes emitted from kernel probes.
type EventType uint8

const (
	EventTCPRTT      EventType = 1
	EventPacketDrop  EventType = 2
	EventSocketStats EventType = 3
	EventTCPState    EventType = 4
)

func (t EventType) String() string {
	switch t {
	case EventTCPRTT:
		return "tcp_rtt"
	case EventPacketDrop:
		return "packet_drop"
	case EventSocketStats:
		return "socket_stats"
	case EventTCPState:
		return "tcp_state"
	default:
		return "unknown"
	}
}

// TCPRTTEvent records latency measurement from tcp_rcv_established and tcp_finish_connect.
type TCPRTTEvent struct {
	SAddr     uint32
	DAddr     uint32
	SPort     uint16
	DPort     uint16
	PID       uint32
	TGID      uint32
	SRTT      uint32 // Smoothed RTT in microseconds
	RTTVar    uint32 // RTT variance in microseconds
	MinRTT    uint32 // Minimum observed RTT in microseconds
	TotalRetr uint32 // Cumulative retransmissions
	Comm      [16]byte
	Timestamp uint64 // Nanoseconds timestamp from bpf_ktime_get_ns
}

// DropReason matches kernel skb drop reason enum.
type DropReason uint32

const (
	DropReasonNotSpecified DropReason = 0
	DropReasonNoSocket     DropReason = 1
	DropReasonPKTTooBig    DropReason = 2
	DropReasonTCPCSUM      DropReason = 3
	DropReasonTCPFilter    DropReason = 4
	DropReasonTCPZeroWin   DropReason = 5
	DropReasonTCPReset     DropReason = 6
	DropReasonQueuePurge   DropReason = 7
	DropReasonNetfilter    DropReason = 8
)

func (r DropReason) String() string {
	switch r {
	case DropReasonNotSpecified:
		return "NOT_SPECIFIED"
	case DropReasonNoSocket:
		return "NO_SOCKET"
	case DropReasonPKTTooBig:
		return "PKT_TOO_BIG"
	case DropReasonTCPCSUM:
		return "TCP_CSUM_ERROR"
	case DropReasonTCPFilter:
		return "TCP_FILTER"
	case DropReasonTCPZeroWin:
		return "TCP_ZERO_WINDOW"
	case DropReasonTCPReset:
		return "TCP_RESET"
	case DropReasonQueuePurge:
		return "QUEUE_PURGE"
	case DropReasonNetfilter:
		return "NETFILTER_DROP"
	default:
		return "UNKNOWN_DROP"
	}
}

// PacketDropEvent captures skb:kfree_skb drop traces.
type PacketDropEvent struct {
	SAddr     uint32
	DAddr     uint32
	SPort     uint16
	DPort     uint16
	Protocol  uint8
	Pad       [3]byte
	Reason    DropReason
	Location  uint64 // Kernel PC address where drop occurred
	Comm      [16]byte
	Timestamp uint64
}

// SocketStatsEvent captures periodic or on-change TCP connection health metrics.
type SocketStatsEvent struct {
	SAddr       uint32
	DAddr       uint32
	SPort       uint16
	DPort       uint16
	BytesAcked  uint64
	BytesRcvd   uint64
	CWND        uint32
	SSTHRESH    uint32
	PktRetrans  uint32
	RcvBufBytes uint32
	SndBufBytes uint32
	TCPState    uint8
	Pad         [3]byte
	Timestamp   uint64
}

// FlowKey uniquely identifies an active TCP connection tuple.
type FlowKey struct {
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
	Proto   string
}

// FormatIP converts uint32 IPv4 address to standard dotted-decimal string.
func FormatIP(addr uint32) string {
	ip := net.IPv4(byte(addr), byte(addr>>8), byte(addr>>16), byte(addr>>24))
	return ip.String()
}
