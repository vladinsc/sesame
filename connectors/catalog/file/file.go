// Package file is a catalog connector that reads tools from a YAML file and watches it for changes by mtime.
// It is the simplest catalog; the credentialstore connector derives the same Tools from credential metadata.
package file

import (
	"context"
	"os"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/vladinsc/sesame/pkg/connector"
)

type doc struct {
	Tools []connector.Tool `yaml:"tools"`
}

// Catalog reads tools from path, caching until the file's mtime changes.
type Catalog struct {
	path  string
	mu    sync.Mutex
	mod   time.Time
	tools []connector.Tool
}

// New returns a catalog reading path.
func New(path string) *Catalog { return &Catalog{path: path} }

func (c *Catalog) Tools(_ context.Context) ([]connector.Tool, error) {
	info, err := os.Stat(c.path)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if info.ModTime().Equal(c.mod) && c.tools != nil {
		return c.tools, nil
	}
	b, err := os.ReadFile(c.path)
	if err != nil {
		return nil, err
	}
	var d doc
	if err := yaml.Unmarshal(b, &d); err != nil {
		return nil, err
	}
	c.tools, c.mod = d.Tools, info.ModTime()
	return c.tools, nil
}
