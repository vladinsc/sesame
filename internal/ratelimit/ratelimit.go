// Package ratelimit is a small per-key sliding-window limiter used to cap logins per user and per tool account.
// It keeps retry storms from reaching the tools (which may lock shared accounts) and bounds abuse.
package ratelimit

import (
	"sync"
	"time"
)

// Limiter allows up to Max events per key within Window.
type Limiter struct {
	max    int
	window time.Duration
	now    func() time.Time

	mu   sync.Mutex
	hits map[string][]time.Time
}

// New returns a limiter.
func New(max int, window time.Duration) *Limiter {
	return &Limiter{max: max, window: window, now: time.Now, hits: make(map[string][]time.Time)}
}

// Allow records and allows an event for key, or returns false if the key is over its limit.
func (l *Limiter) Allow(key string) bool {
	now := l.now()
	cutoff := now.Add(-l.window)
	l.mu.Lock()
	defer l.mu.Unlock()
	times := l.hits[key][:0]
	for _, t := range l.hits[key] {
		if t.After(cutoff) {
			times = append(times, t)
		}
	}
	if len(times) >= l.max {
		l.hits[key] = times
		return false
	}
	l.hits[key] = append(times, now)
	return true
}

// Reap drops empty/old entries so the map doesn't grow without bound. Call periodically.
func (l *Limiter) Reap() {
	cutoff := l.now().Add(-l.window)
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, ts := range l.hits {
		live := ts[:0]
		for _, t := range ts {
			if t.After(cutoff) {
				live = append(live, t)
			}
		}
		if len(live) == 0 {
			delete(l.hits, k)
		} else {
			l.hits[k] = live
		}
	}
}
