package decoder

import (
	"fmt"
	"sync/atomic"
)

// Stats holds atomic counters for the decoder. The counters are safe
// for concurrent use so the periodic stats logger can read them while
// the receive loop updates them.
type Stats struct {
	Received atomic.Uint64
	Decoded  atomic.Uint64
	Written  atomic.Uint64
	Errors   atomic.Uint64
}

// String returns a human-readable summary of the counters.
func (s *Stats) String() string {
	return s.Snapshot().String()
}

// Snapshot returns a point-in-time copy of the counters.
func (s *Stats) Snapshot() StatsSnapshot {
	return StatsSnapshot{
		Received: s.Received.Load(),
		Decoded:  s.Decoded.Load(),
		Written:  s.Written.Load(),
		Errors:   s.Errors.Load(),
	}
}

// StatsSnapshot is a point-in-time copy of the decoder counters.
type StatsSnapshot struct {
	Received uint64
	Decoded  uint64
	Written  uint64
	Errors   uint64
}

// String returns a human-readable summary of the snapshot.
func (s StatsSnapshot) String() string {
	return fmt.Sprintf("received=%d decoded=%d written=%d errors=%d",
		s.Received, s.Decoded, s.Written, s.Errors)
}
