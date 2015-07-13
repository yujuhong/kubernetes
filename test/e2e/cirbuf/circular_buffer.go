/*
Copyright 2015 The Kubernetes Authors All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cirbuf

import (
	"sync"
)

// CircularBuffer is a simple buffer that can store up to maxSize items by
// overwriting the oldest item at Push if necessary. There is no explicit
// method to remove (e.g. "Pop") data from the buffer, but instead, callers can
// read the latest item or the entire array. This prevents the need of more
// complex implementation, or the need to pre-allocate maxSize array at when
// initializing the buffer. One example of using circular buffer is to cache
// periodically-generated stats which can be examined at any time.
type CircularBuffer struct {
	lock    sync.RWMutex
	items   []interface{}
	head    int
	tail    int
	count   int
	maxSize int
}

func NewCircularBuffer(maxSize int) *CircularBuffer {
	return &CircularBuffer{maxSize: maxSize}
}

// Push stores a new item into the internal storage. It may involve array
// resizing or overwriting the oldest item.
func (c *CircularBuffer) Push(item interface{}) {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.count == c.maxSize/2 {
		// Resizing the items ourselvse to prevent automatic resizing that may
		// go beyond c.maxSize.
		t := make([]interface{}, len(c.items), c.maxSize)
		copy(t, c.items)
		c.items = t
	}
	if c.count < c.maxSize {
		// Append to the slice and let automatic resizing handles the rest.
		c.items = append(c.items, item)
		c.tail = (c.tail + 1) % c.maxSize
		c.count += 1
		return
	}
	// We've reached the maximum size. Overwrite the oldest item at head.
	c.items[c.head] = item
	c.head = (c.head + 1) % c.maxSize
	c.tail = c.head
}

// GetCount returns the number of items in the buffer.
func (c *CircularBuffer) GetCount() int {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.count
}

// GetLatest returns the latest item inserted before tail.
func (c *CircularBuffer) GetLatest() interface{} {
	c.lock.RLock()
	defer c.lock.RUnlock()
	if c.count == 0 {
		return nil
	}
	return c.items[(c.tail-1+c.maxSize)%c.maxSize]
}

// List returns the items in the buffer as a slice.
func (c *CircularBuffer) List() []interface{} {
	c.lock.RLock()
	defer c.lock.RUnlock()
	items := make([]interface{}, 0, c.count)
	for i := 0; i < c.count; i++ {
		items = append(items, c.items[(c.head+i)%c.maxSize])
	}
	return items
}
