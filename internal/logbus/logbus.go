// Package logbus is a tiny fan-out for log lines. The HTTP layer subscribes to
// it and streams entries to the browser console over Server-Sent Events.
package logbus

import (
	"sync"
	"time"
)

// Entry is a single timestamped log line.
type Entry struct {
	Time  string `json:"time"` // HH:MM:SS
	Msg   string `json:"msg"`
	Level string `json:"level"` // INFO/OK/WARN/ERROR/ACCENT/DIM
}

// Bus fans out log entries to all current subscribers and keeps a small
// backlog so a freshly-connected browser sees recent history.
type Bus struct {
	mu      sync.Mutex
	subs    map[chan Entry]struct{}
	history []Entry
}

// New returns an empty Bus.
func New() *Bus {
	return &Bus{subs: make(map[chan Entry]struct{})}
}

// Log publishes a line at the given level. level defaults to "INFO" if empty.
func (b *Bus) Log(msg, level string) {
	if level == "" {
		level = "INFO"
	}
	e := Entry{Time: time.Now().Format("15:04:05"), Msg: msg, Level: level}
	b.mu.Lock()
	b.history = append(b.history, e)
	if len(b.history) > 300 {
		b.history = b.history[len(b.history)-300:]
	}
	for ch := range b.subs {
		select {
		case ch <- e:
		default: // drop for a slow subscriber rather than block the producer
		}
	}
	b.mu.Unlock()
}

// Subscribe registers a new subscriber and returns its channel plus the
// current backlog. Call the returned cancel func to unsubscribe.
func (b *Bus) Subscribe() (<-chan Entry, []Entry, func()) {
	ch := make(chan Entry, 256)
	b.mu.Lock()
	b.subs[ch] = struct{}{}
	backlog := make([]Entry, len(b.history))
	copy(backlog, b.history)
	b.mu.Unlock()

	cancel := func() {
		b.mu.Lock()
		if _, ok := b.subs[ch]; ok {
			delete(b.subs, ch)
			close(ch)
		}
		b.mu.Unlock()
	}
	return ch, backlog, cancel
}
