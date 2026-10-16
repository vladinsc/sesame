// Package metrics is a minimal, dependency-free Prometheus text-format exporter for counters and
// duration sums. sesame only needs a handful of series; avoiding the client library keeps the
// supply-chain surface small.
package metrics

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Registry holds counters keyed by name and label set.
type Registry struct {
	mu       sync.Mutex
	counters map[string]map[string]float64 // name -> rendered labels -> value
	help     map[string]string
}

// New returns an empty registry.
func New() *Registry {
	return &Registry{counters: map[string]map[string]float64{}, help: map[string]string{}}
}

// Describe sets the HELP text of a metric.
func (r *Registry) Describe(name, help string) {
	r.mu.Lock()
	r.help[name] = help
	r.mu.Unlock()
}

// Add increments counter name{labels} by v. labels are key, value pairs.
func (r *Registry) Add(name string, v float64, labels ...string) {
	key := render(labels)
	r.mu.Lock()
	m := r.counters[name]
	if m == nil {
		m = map[string]float64{}
		r.counters[name] = m
	}
	m[key] += v
	r.mu.Unlock()
}

// Inc increments a counter by one.
func (r *Registry) Inc(name string, labels ...string) { r.Add(name, 1, labels...) }

// ObserveDuration adds to name_seconds_sum and name_seconds_count.
func (r *Registry) ObserveDuration(name string, d time.Duration, labels ...string) {
	r.Add(name+"_seconds_sum", d.Seconds(), labels...)
	r.Add(name+"_seconds_count", 1, labels...)
}

// Handler serves the registry in Prometheus text format.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		r.mu.Lock()
		defer r.mu.Unlock()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		names := make([]string, 0, len(r.counters))
		for n := range r.counters {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			if h := r.help[n]; h != "" {
				fmt.Fprintf(w, "# HELP %s %s\n", n, h)
			}
			fmt.Fprintf(w, "# TYPE %s counter\n", n)
			keys := make([]string, 0, len(r.counters[n]))
			for k := range r.counters[n] {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				fmt.Fprintf(w, "%s%s %g\n", n, k, r.counters[n][k])
			}
		}
	})
}

func render(labels []string) string {
	if len(labels) < 2 {
		return ""
	}
	parts := make([]string, 0, len(labels)/2)
	for i := 0; i+1 < len(labels); i += 2 {
		v := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(labels[i+1])
		parts = append(parts, fmt.Sprintf(`%s="%s"`, labels[i], v))
	}
	return "{" + strings.Join(parts, ",") + "}"
}
