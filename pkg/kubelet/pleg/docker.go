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
	kubecontainer "k8s.io/kubernetes/pkg/kubelet/container"
	"k8s.io/kubernetes/pkg/kubelet/dockertools"
	"k8s.io/kubernetes/pkg/types"
	"k8s.io/kubernetes/pkg/util"
)

// For testability.
type DockerContainerGetter interface {
	GetPods(all bool) ([]*kubecontainer.Pod, error)
	ExamineContainer(dockerID string) (*dockertools.ContainerExaminationResult, error)
}

// DockerPLEG implements PodLifecycleEventGenerator for the Docker container
// runtime. When receiving an upstream container event, it inspects the
// container and generate corresponding pod event.
//
// It should be noted that the container state may have changed after receving
// a container event, but before DockerPLEG inspects the container. However,
// the separate inspection is needed because the upstream may not provide all
// necessary information (e.g., pod ID). The subscribers are expected to deal
// with such inconsistency.
type DockerPLEG struct {
	// The period for relisting.
	relistPeriod time.Duration
	// The timestamp of the last relist.
	relistTimestamp time.Time
	// The upstream container event watcher.
	upstreamWatcher ContainerEventWatcher
	upstreamCh      <-chan *ContainerEvent
	// The channel for the subscriber to receive.
	// TODO: Support multiple subscribers.
	eventChannel chan *PodLifecycleEvent
	// The underlying container runtime.
	// TODO(yujuhong): Replace this with kubecontainer.Runtime, or define a new
	// interface.
	runtime DockerContainerGetter
	// The set of containers (IDs) that we know are alive.
	aliveContainers util.StringSet
	// The set of containers (IDs) that we know are dead.
	deadContainers util.StringSet
}

var _ PodLifecycleEventGenerator = &DockerPLEG{}

func NewDockerPLEG(upstreamWatcher ContainerEventWatcher, runtime DockerContainerGetter, channelCapacity int,
	relistPeriod time.Duration) *DockerPLEG {
	return &DockerPLEG{
		relistPeriod:    relistPeriod,
		upstreamWatcher: upstreamWatcher,
		runtime:         runtime,
		eventChannel:    make(chan *PodLifecycleEvent, channelCapacity),
		aliveContainers: util.NewStringSet(),
		deadContainers:  util.NewStringSet(),
	}
}

const (
	// How many times to retry when starting up the upstream watcher.
	startRetryLimit = 3
)

// Returns a channel from which the subscriber can recieve PodLifecycleEvent
// events.
func (d *DockerPLEG) Watch() chan *PodLifecycleEvent {
	return d.eventChannel
}

// Instruct DockerPLEG to start watch upstrem for changes (and generate pod
// lifcycle events to the downstream channel).
func (d *DockerPLEG) Start() {
	// We need to start watching the upstream before relisting to ensure
	// that we don't miss events. However, we should not start processing
	// those events until relist is completed so that we can deduplicate
	// events.
	d.startWatchingUpstream()
	d.bootstrap()
	glog.V(3).Infof("DockerPLEG: Bootstrapping completed.")
	go util.Until(d.doWork, 0, util.NeverStop)
}

// startWatchingUpstrea starts watching upstream for container changes, and
// sets the upstreamCh channel.
func (d *DockerPLEG) startWatchingUpstream() {
	// TODO(yujuhong): Make sure there is enough channel capacity to buffer
	// the events, or we should buffer it internally.
	for i := 0; i < startRetryLimit; i++ {
		ch, err := d.upstreamWatcher.Watch()
		if err == nil {
			d.upstreamCh = ch
			break
		}
		glog.Warningf("Unable to watch upstream %v: %v", d.upstreamWatcher, err)
		time.Sleep(time.Second * 2)
	}
}

func (d *DockerPLEG) doWork() {
	d.Relist()
	for {
		select {
		case e, ok := <-d.upstreamCh:
			if !ok {
				glog.Infof("DockerPLEG: Upstream channel closed")
				d.startWatchingUpstream()
				return
			}
			glog.V(3).Infof("DockerPLEG: Received an event from upstream: %+v", e)
			if e.Timestamp.Before(d.relistTimestamp) {
				// Any event that is older than the last relist timestamp
				// is considered outdated, and should be discarded
				glog.V(3).Infof("DockerPLEG: Discarding outdated event %+v", e)
				break
			}
			d.processEvent(e)
		case <-time.After(d.relistPeriod):
			glog.V(3).Infof("DockerPLEG: Relisting")
			d.Relist()
		}
	}
}

func (d *DockerPLEG) processEvent(e *ContainerEvent) {
	switch e.Type {
	case ContainerEventStarted:
		d.handleContainerStarted(e)
	case ContainerEventStopped:
		d.handleContainerStopped(e)
	default:
		glog.Errorf("DockerPLEG: Unknown event: %+v", e)
	}
}

func (d *DockerPLEG) Relist() {
	oldAlive := d.aliveContainers
	oldDead := d.deadContainers
	// Set the relist timestamp.
	d.relistTimestamp = time.Now()
	alive, dead, err := d.getAliveAndDeadConainerSets()
	if err != nil {
		glog.Errorf("DockerPLEG: Unable to get pods from the container runtime: %v", err)
		return
	}
	// A set of dead containers whose existence we weren't aware of prior to
	// relist. This means that we may have missed both the creation and deletion
	// events of a container. We'd send out creation/deletion events for both
	// of them.
	missed := dead.Difference(oldDead).Difference(oldAlive)

	// Generate corresponding container events, which will be treated the same
	// way as the events from upstream. Note that the internal alive/dead
	// container sets will be modified accordingly when processing the events.
	started := alive.Difference(oldAlive)
	stopped := oldAlive.Difference(alive)
	if started.Len() != 0 || stopped.Len() != 0 || missed.Len() != 0 {
		glog.V(2).Infof("DockerPLEG: Discovered missing events; started: %v, stopped: %v, missed: %v",
			started.List(), stopped.List(), missed.List())
	}
	for _, c := range started.Union(missed).List() {
		d.processEvent(&ContainerEvent{
			ID:        c,
			Timestamp: d.relistTimestamp,
			Type:      ContainerEventStarted,
		})
	}
	for _, c := range stopped.Union(missed).List() {
		d.processEvent(&ContainerEvent{
			ID:        c,
			Timestamp: d.relistTimestamp,
			Type:      ContainerEventStopped,
		})
	}
}

func (d *DockerPLEG) getAliveAndDeadConainerSets() (util.StringSet, util.StringSet, error) {
	allPods, err := d.runtime.GetPods(true)
	if err != nil {
		return nil, nil, err
	}
	pods, err := d.runtime.GetPods(false)
	if err != nil {
		return nil, nil, err
	}
	all := buildContainerSet(allPods)
	alive := buildContainerSet(pods)
	return alive, all.Difference(alive), nil
}

// bootstrap relists and sends out PodSync events for each pod.
func (d *DockerPLEG) bootstrap() {
	// We call GetPods() directly (instead of Relist()) because all we want to
	// skip regular container event processing, and just sends out a PodSync
	// event for each pod.
	d.relistTimestamp = time.Now()
	alive, dead, err := d.getAliveAndDeadConainerSets()
	if err != nil {
		glog.Errorf("DockerPLEG: Unable to get pods from the container runtime: %v", err)
		return
	}
	d.aliveContainers = alive
	d.deadContainers = dead
	for _, podID := range d.aliveContainers.List() {
		// TODO(yujuhong): Insert some time to interleave the pod workers?
		d.eventChannel <- &PodLifecycleEvent{ID: types.UID(podID), Type: PodSync}
	}
}

func (d *DockerPLEG) handleContainerStarted(e *ContainerEvent) {
	if d.aliveContainers.Has(e.ID) && !d.deadContainers.Has(e.ID) {
		// TODO(yujuhong): Why would we see duplicated events?
		glog.Warningf("DockerPLEG: Received duplicated event: %#v", e)
		return
	}
	d.aliveContainers.Insert(e.ID)

	// We need to derive some information from the container ID: pod ID,
	// whether the container is a network container.
	result, err := d.runtime.ExamineContainer(e.ID)
	if err != nil {
		glog.Errorf("DockerPLEG: Unable to examine container %q: %v", e.ID, err)
		return
	}
	pod := result.Pod
	container := result.Pod.Containers[0]
	if result.IsInfraContainer {
		d.eventChannel <- &PodLifecycleEvent{ID: pod.ID, Type: NetworkSetupCompleted}
	} else {
		d.eventChannel <- &PodLifecycleEvent{ID: pod.ID, Type: ContainerStarted, Data: container.Name}
	}
}

func (d *DockerPLEG) handleContainerStopped(e *ContainerEvent) {
	if !d.aliveContainers.Has(e.ID) && d.deadContainers.Has(e.ID) {
		// TODO(yjhong): Why would we see duplicated events?
		glog.V(4).Infof("DockerPLEG: Received duplicated event: %#v", e)
		return
	}
	d.aliveContainers.Delete(e.ID)
	d.deadContainers.Insert(e.ID)

	// We need to derive some information from the container ID: pod ID,
	// whether the container is a network container.
	result, err := d.runtime.ExamineContainer(e.ID)
	if err != nil {
		glog.Errorf("DockerPLEG: Unable to examine container %q: %v", e.ID, err)
		return
	}

	// DEBUGGING ONLY
	pods, err := d.runtime.GetPods(false)
	for _, p := range pods {
		if p.ID == result.Pod.ID {
			for _, c := range p.Containers {
				if types.UID(e.ID) == c.ID {
					glog.Errorf("DockerPLEG: dead container is still in docker ps %v", e.ID)
				}
				break
			}
			break
		}
	}

	pod := result.Pod
	container := result.Pod.Containers[0]
	if result.IsInfraContainer {
		d.eventChannel <- &PodLifecycleEvent{ID: pod.ID, Type: NetworkFailed}
	} else {
		d.eventChannel <- &PodLifecycleEvent{ID: pod.ID, Type: ContainerStopped, Data: container.Name}
	}
}

func buildContainerSet(pods []*kubecontainer.Pod) util.StringSet {
	cset := util.NewStringSet()
	for _, p := range pods {
		for _, c := range p.Containers {
			cset.Insert(string(c.ID))
		}
	}
	return cset
}
