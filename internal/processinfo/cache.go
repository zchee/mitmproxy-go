// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package processinfo

import (
	"container/list"
	"crypto/sha256"
	"fmt"
	"slices"
	"sync"
)

type cachedPath struct {
	path   string
	digest [sha256.Size]byte
}

type cachedIcon struct {
	png  []byte
	refs int
}

type iconCache struct {
	mu       sync.Mutex
	paths    map[string]*list.Element
	icons    map[[sha256.Size]byte]*cachedIcon
	lru      list.List
	bytes    int
	maxPaths int
	maxBytes int
}

func newIconCache(maxPaths, maxBytes int) *iconCache {
	return &iconCache{
		paths: make(map[string]*list.Element), icons: make(map[[sha256.Size]byte]*cachedIcon),
		maxPaths: maxPaths, maxBytes: maxBytes,
	}
}

func (c *iconCache) get(path string, load func(string) ([]byte, error)) ([]byte, error) {
	c.mu.Lock()
	if entry, exists := c.paths[path]; exists {
		c.lru.MoveToFront(entry)
		data := slices.Clone(c.icons[entry.Value.(cachedPath).digest].png)
		c.mu.Unlock()
		return data, nil
	}
	c.mu.Unlock()

	data, err := load(path)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data) > maxPNGBytes || len(data) > c.maxBytes || c.maxPaths < 1 {
		return nil, fmt.Errorf("processinfo: icon size %d exceeds cache bounds", len(data))
	}
	// The loader may reuse its result after returning, so the cache owns a copy.
	data = slices.Clone(data)
	digest := sha256.Sum256(data)

	c.mu.Lock()
	defer c.mu.Unlock()
	if entry, exists := c.paths[path]; exists {
		c.lru.MoveToFront(entry)
		return slices.Clone(c.icons[entry.Value.(cachedPath).digest].png), nil
	}
	for len(c.paths) >= c.maxPaths || (c.icons[digest] == nil && c.bytes+len(data) > c.maxBytes) {
		entry := c.lru.Back()
		old := entry.Value.(cachedPath)
		delete(c.paths, old.path)
		c.lru.Remove(entry)
		icon := c.icons[old.digest]
		icon.refs--
		if icon.refs == 0 {
			c.bytes -= len(icon.png)
			delete(c.icons, old.digest)
		}
	}
	icon := c.icons[digest]
	if icon == nil {
		icon = &cachedIcon{png: data}
		c.icons[digest] = icon
		c.bytes += len(data)
	}
	icon.refs++
	c.paths[path] = c.lru.PushFront(cachedPath{path: path, digest: digest})
	return slices.Clone(icon.png), nil
}
