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

package pleg

import (
	"reflect"
	"testing"
	"time"

	kubecontainer "k8s.io/kubernetes/pkg/kubelet/container"
)

type TestGenericPLEG struct {
	pleg    *GenericPLEG
	runtime *kubecontainer.FakeRuntime
}

func newTestGenericPLEG() *TestGenericPLEG {
	fakeRuntime := &kubecontainer.FakeRuntime{}
	// The channel capacity should be large enough to hold all events in a
	// single test.
	pleg := NewGenericPLEG(fakeRuntime, 100, time.Hour)
	return &TestGenericPLEG{pleg: pleg, runtime: fakeRuntime}
}

func getEventsFromChannel(ch <-chan *PodLifecycleEvent) []*PodLifecycleEvent {
	events := []*PodLifecycleEvent{}
	for len(ch) > 0 {
		e := <-ch
		events = append(events, e)
	}
	return events
}

func TestGenericPLEGRelist(t *testing.T) {
	testPleg := newTestGenericPLEG()
	pleg, runtime := testPleg.pleg, testPleg.runtime
	ch := pleg.Watch()

	// The first relist should send a PodSync event to each pod.
	runtime.PodList = []*kubecontainer.Pod{
		{
			ID:        "1234",
			Name:      "qux",
			Namespace: "ns",
		},
		{
			ID:        "4567",
			Name:      "foo",
			Namespace: "ns",
		},
	}
	pleg.Relist()
	expected := []*PodLifecycleEvent{
		{ID: "1234", Type: PodSync},
		{ID: "4567", Type: PodSync},
	}
	actual := getEventsFromChannel(ch)
	if !reflect.DeepEqual(expected, actual) {
		t.Fatalf("Expected: %#v, got: %#v", expected, actual)
	}

	// The second relist should not send out any event because the pod list has
	// not changed.
	pleg.Relist()
	if len(ch) != 0 {
		t.Fatalf("Expected 0 event in the channel, got %d", len(ch))
	}

	// Add a new pod and relist to get the new event.
	runtime.PodList = append(runtime.PodList, &kubecontainer.Pod{
		ID:        "7890",
		Name:      "bar",
		Namespace: "ns",
	})
	pleg.Relist()
	expected = []*PodLifecycleEvent{{ID: "7890", Type: PodSync}}
	actual = getEventsFromChannel(ch)
	if !reflect.DeepEqual(expected, actual) {
		t.Fatalf("Expected: %#v, got: %#v", expected, actual)
	}
}
