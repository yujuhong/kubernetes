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

package prober

import (
	"time"

	"github.com/golang/glog"
	"k8s.io/kubernetes/pkg/api"
	kubecontainer "k8s.io/kubernetes/pkg/kubelet/container"
	"k8s.io/kubernetes/pkg/kubelet/prober/results"
	"k8s.io/kubernetes/pkg/kubelet/util/format"
	"k8s.io/kubernetes/pkg/util/runtime"
)

// worker handles the periodic probing of its assigned container. Each worker has a go-routine
// associated with it which runs the probe loop until the container permanently terminates, or the
// stop channel is closed.
type worker struct {
	// Channel for stopping the probe, it should be closed to trigger a stop.
	stop chan struct{}

	// The pod containing this probe (read-only)
	pod *api.Pod

	// The container to probe (read-only)
	container api.Container

	containerID kubecontainer.ContainerID

	// Describes the probe configuration (read-only)
	spec *api.Probe

	// The type of the worker.
	probeType probeType

	// The probe value during the initial delay.
	initialValue results.Result

	// Where to store this workers results.
	resultsManager results.Manager
	probeManager   *manager

	// The last probe result for this worker.
	lastResult results.Result
	// How many times in a row the probe has returned the same result.
	resultRun int
}

// Creates and starts a new probe worker.
func newWorker(
	m *manager,
	probeType probeType,
	pod *api.Pod,
	container api.Container,
	containerID kubecontainer.ContainerID,
) *worker {

	w := &worker{
		stop:         make(chan struct{}),
		pod:          pod,
		container:    container,
		probeType:    probeType,
		probeManager: m,
		containerID:  containerID,
	}

	switch probeType {
	case readiness:
		w.spec = container.ReadinessProbe
		w.resultsManager = m.readinessManager
		w.initialValue = results.Failure
	case liveness:
		w.spec = container.LivenessProbe
		w.resultsManager = m.livenessManager
		w.initialValue = results.Success
	}

	return w
}

// run periodically probes the container.
func (w *worker) run() {
	time.Sleep(time.Duration(int64(w.spec.InitialDelaySeconds)) * time.Second)

	probeTicker := time.NewTicker(time.Duration(int64(w.spec.PeriodSeconds)) * time.Second)

	defer func() {
		// Clean up.
		probeTicker.Stop()
		w.resultsManager.Remove(w.containerID)
		w.probeManager.removeWorker(w.pod.UID, w.container.Name, w.probeType)
	}()

probeLoop:
	for w.doProbe() {
		// Wait for next probe tick.
		select {
		case <-w.stop:
			break probeLoop
		case <-probeTicker.C:
			// continue
		}
	}
}

// doProbe probes the container once and records the result.
// Returns whether the worker should continue.
func (w *worker) doProbe() (keepGoing bool) {
	defer runtime.HandleCrash(func(_ interface{}) { keepGoing = true })
	status, err := w.probeManager.runtimeCache.Get(w.pod.UID)
	if err != nil {
		glog.V(4).Infof("Probe: unable to get pod status for %q/%q: %v", format.Pod(w.pod), w.containerID.ID, err)
		return true
	}
	result, err := w.probeManager.prober.probe(w.probeType, w.pod, *status, w.container, w.containerID)
	if err != nil {
		// Prober error, throw away the result.
		glog.V(4).Infof("Probe: failed probing for pod %q/%q: %v", format.Pod(w.pod), w.containerID.ID, err)
		return true
	}

	if w.lastResult == result {
		w.resultRun++
	} else {
		w.lastResult = result
		w.resultRun = 1
	}

	if (result == results.Failure && w.resultRun < w.spec.FailureThreshold) ||
		(result == results.Success && w.resultRun < w.spec.SuccessThreshold) {
		// Success or failure is below threshold - leave the probe state unchanged.
		return true
	}

	w.resultsManager.Set(w.containerID, result, w.pod)

	return true
}
