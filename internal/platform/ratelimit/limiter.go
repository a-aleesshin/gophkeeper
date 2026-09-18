package ratelimit

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const staleAfter = 10 * time.Minute

type Limiter struct {
	mu      sync.Mutex
	entries map[string]*entry
	rate    rate.Limit
	burst   int
	now     func() time.Time
}

type entry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func New(r rate.Limit, burst int) *Limiter {
	return &Limiter{
		entries: make(map[string]*entry),
		rate:    r,
		burst:   burst,
		now:     time.Now,
	}
}

func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	e, ok := l.entries[key]
	if !ok {
		l.purgeLocked(now)
		e = &entry{limiter: rate.NewLimiter(l.rate, l.burst)}
		l.entries[key] = e
	}
	e.lastSeen = now
	return e.limiter.Allow()
}

func (l *Limiter) purgeLocked(now time.Time) {
	for key, e := range l.entries {
		if now.Sub(e.lastSeen) > staleAfter {
			delete(l.entries, key)
		}
	}
}
