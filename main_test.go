package main

import (
	"testing"
	"time"

	"github.com/Talgarr/Whence-Touche/internal/tracer"
)

// TestSessionReady covers the dwell logic that suppresses the issue #1
// "flash": a brief pre-PIN burst must not notify, while a sustained
// touch-wait must.
func TestSessionReady(t *testing.T) {
	const (
		threshold = 3
		delay     = 500 * time.Millisecond
	)
	base := time.Unix(1000, 0)

	cases := []struct {
		name      string
		count     int
		span      time.Duration
		shown     bool
		wantReady bool
	}{
		{
			name:      "below threshold never notifies",
			count:     2,
			span:      time.Second,
			wantReady: false,
		},
		{
			name:      "brief pre-PIN burst is suppressed",
			count:     5,
			span:      10 * time.Millisecond, // many packets, but over in a blink
			wantReady: false,
		},
		{
			name:      "sustained touch-wait notifies",
			count:     20,
			span:      800 * time.Millisecond,
			wantReady: true,
		},
		{
			name:      "boundary: exactly threshold and exactly delay notifies",
			count:     threshold,
			span:      delay,
			wantReady: true,
		},
		{
			name:      "just under the delay is suppressed",
			count:     threshold,
			span:      delay - time.Millisecond,
			wantReady: false,
		},
		{
			name:      "already shown does not re-trigger",
			count:     20,
			span:      time.Second,
			shown:     true,
			wantReady: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &session{
				count:     tc.count,
				firstSeen: base,
				lastSeen:  base.Add(tc.span),
				shown:     tc.shown,
			}
			if got := s.ready(threshold, delay); got != tc.wantReady {
				t.Errorf("ready(count=%d, span=%v, shown=%v) = %v, want %v",
					tc.count, tc.span, tc.shown, got, tc.wantReady)
			}
		})
	}
}

// TestHandleEventAccumulates verifies that handleEvent tracks a session's
// timeline (firstSeen pinned to the first event, count incrementing) without
// notifying while activity stays brief — the not-yet-ready path that keeps a
// pre-PIN burst quiet.
func TestHandleEventAccumulates(t *testing.T) {
	sessions := make(map[sessionKey]*session)
	ev := tracer.Event{PID: 4242, Source: tracer.SourceHIDRaw}

	// A short burst of events, all within the same instant for test purposes:
	// count climbs past the threshold but the span stays ~0, so nothing shows.
	for i := 0; i < 5; i++ {
		handleEvent(nil, sessions, ev, 3, 500*time.Millisecond)
	}

	s := sessions[sessionKey{ev.Source, ev.PID}]
	if s == nil {
		t.Fatal("expected a session to be recorded")
	}
	if s.count != 5 {
		t.Errorf("count = %d, want 5", s.count)
	}
	if s.shown {
		t.Error("a sub-delay burst must not notify (would flash on PIN entry)")
	}
	if s.firstSeen.After(s.lastSeen) {
		t.Errorf("firstSeen %v should not be after lastSeen %v", s.firstSeen, s.lastSeen)
	}
}
