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
	"reflect"
	"testing"
)

func convertToIntList(buf *CircularBuffer) []int {
	items := buf.List()
	list := make([]int, 0, len(items))
	for i := range items {
		list = append(list, *items[i].(*int))
	}
	return list
}

func verifyBufferContent(t *testing.T, buf *CircularBuffer, expected []int) {
	if buf.GetCount() != len(expected) {
		t.Errorf("incorrect buffer length; expected %d, got %d", len(expected), buf.GetCount())
	}
	actualItem := *buf.GetLatest().(*int)
	expectedItem := expected[len(expected)-1]
	if actualItem != expectedItem {
		t.Errorf("incorrect last item; expected %d, got %d", expectedItem, actualItem)
	}
	actualList := convertToIntList(buf)
	if !reflect.DeepEqual(actualList, expected) {
		t.Errorf("incorrect buffer content; expected %#v, got %#v", expected, actualList)
	}
	if cap(buf.items) > buf.maxSize {
		t.Fatalf("buffer capacity %d exceeds maxSize %d", cap(buf.items), buf.maxSize)
	}
}

func TestBasicInserts(t *testing.T) {
	maxSize := 5
	buf := NewCircularBuffer(maxSize)
	for i := 0; i < maxSize; i++ {
		item := i
		buf.Push(&item)
	}
	verifyBufferContent(t, buf, []int{0, 1, 2, 3, 4})

	for i := maxSize; i < maxSize+3; i++ {
		item := i
		buf.Push(&item)
	}
	verifyBufferContent(t, buf, []int{3, 4, 5, 6, 7})
}
