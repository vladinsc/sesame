package ratelimit

import (
	"testing"
	"time"
)

func TestSlidingWindow(t *testing.T) {
	now := time.Unix(1000, 0)
	l := New(2, time.Minute)
	l.now = func() time.Time { return now }

	if !l.Allow("u") || !l.Allow("u") {
		t.Fatal("first two should be allowed")
	}
	if l.Allow("u") {
		t.Fatal("third within window should be denied")
	}
	if !l.Allow("other") {
		t.Fatal("a different key is independent")
	}
	now = now.Add(61 * time.Second) // window passed
	if !l.Allow("u") {
		t.Fatal("after the window it should allow again")
	}
}

func TestReap(t *testing.T) {
	now := time.Unix(0, 0)
	l := New(5, time.Minute)
	l.now = func() time.Time { return now }
	l.Allow("a")
	now = now.Add(2 * time.Minute)
	l.Reap()
	l.mu.Lock()
	_, ok := l.hits["a"]
	l.mu.Unlock()
	if ok {
		t.Fatal("stale key should be reaped")
	}
}
