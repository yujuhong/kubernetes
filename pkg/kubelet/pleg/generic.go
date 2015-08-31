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
	"time"

	"github.com/golang/glog"
	"k8s.io/kubernetes/pkg/api"
	kubecontainer "k8s.io/kubernetes/pkg/kubelet/container"
	"k8s.io/kubernetes/pkg/types"
	"k8s.io/kubernetes/pkg/util"
)

// GenericPLEG is a extremely simple generic PLEG that periodically generates
// PodSync events for all pods. It should be be used as temporary replacement
// for container runtimes do not support a proper event generator yet.
type GenericPLEG struct {
	// The period for relisting.
	relistPeriod time.Duration
	runtime      kubecontainer.Runtime
	eventChannel chan *PodLifecycleEvent
	pods         map[types.UID]*kubecontainer.Pod
}

var _ PodLifecycleEventGenerator = &GenericPLEG{}

func NewGenericPLEG(runtime kubecontainer.Runtime, channelCapacity int,
	relistPeriod time.Duration) *GenericPLEG {
	return &GenericPLEG{
		relistPeriod: relistPeriod,
		runtime:      runtime,
		eventChannel: make(chan *PodLifecycleEvent, channelCapacity),
		pods:         make(map[types.UID]*kubecontainer.Pod),
	}
}

// Returns a channel from which the subscriber can recieve PodLifecycleEvent
// events.
func (d *GenericPLEG) Watch() chan *PodLifecycleEvent {
	return d.eventChannel
}

func (d *GenericPLEG) doWork() {
	select {
	case <-time.After(d.relistPeriod):
		glog.V(3).Infof("GenericPLEG: Relisting")
		d.Relist()
	}
}

// Start spawns a goroutine to relist periodically.
func (d *GenericPLEG) Start() {
	d.Relist()
	go util.Until(d.doWork, 0, util.NeverStop)
}

// Relist relists and sends out PodSync events for each pod.
func (d *GenericPLEG) Relist() {
	// We get *all* pods here, including terminated pods. The subscriber is
	// expected to handle irrelevant events.
	pods, err := d.runtime.GetPods(true)
	if err != nil {
		glog.Errorf("GenericPLEG: Unable to retrieve pods: %v", err)
		return
	}

	processed := util.NewStringSet()
	for _, pod := range pods {
		processed.Insert(string(pod.ID))
		if existingPod, ok := d.pods[pod.ID]; ok && api.Semantic.DeepEqual(existingPod, pod) {
			// Nothing has changed.
			continue
		}
		d.pods[pod.ID] = pod
		d.eventChannel <- &PodLifecycleEvent{ID: pod.ID, Type: PodSync}
	}
	// All pods that are in the new list have been processed. Look for pods
	// that are in the old list, but no longer in the new list.
	for _, pod := range d.pods {
		if processed.Has(string(pod.ID)) {
			continue
		}
		d.eventChannel <- &PodLifecycleEvent{ID: pod.ID, Type: PodSync}
	}
}
