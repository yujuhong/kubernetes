/*
Copyright 2014 The Kubernetes Authors All rights reserved.

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

package status

import (
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/golang/glog"
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/api/errors"
	"k8s.io/kubernetes/pkg/api/unversioned"
	client "k8s.io/kubernetes/pkg/client/unversioned"
	kubecontainer "k8s.io/kubernetes/pkg/kubelet/container"
	kubepod "k8s.io/kubernetes/pkg/kubelet/pod"
	kubetypes "k8s.io/kubernetes/pkg/kubelet/types"
	"k8s.io/kubernetes/pkg/kubelet/util/format"
	"k8s.io/kubernetes/pkg/types"
	"k8s.io/kubernetes/pkg/util"
)

// A wrapper around api.PodStatus that includes a version to enforce that stale pod statuses are
// not sent to the API server.
type versionedPodStatus struct {
	status api.PodStatus
	// Monotonically increasing version number (per pod).
	version uint64
	// Pod name & namespace, for sending updates to API server.
	podName      string
	podNamespace string
}

type podStatusSyncRequest struct {
	podUID types.UID
	status versionedPodStatus
}

// Updates pod statuses in apiserver. Writes only when new status has changed.
// All methods are thread-safe.
type manager struct {
	kubeClient client.Interface
	podManager kubepod.Manager
	// Map from pod UID to sync status of the corresponding pod.
	podStatuses      map[types.UID]versionedPodStatus
	podStatusesLock  sync.RWMutex
	podStatusChannel chan podStatusSyncRequest
	// Map from (mirror) pod UID to latest status version successfully sent to the API server.
	// apiStatusVersions must only be accessed from the sync thread.
	apiStatusVersions map[types.UID]uint64
}

// status.Manager is the Source of truth for kubelet pod status, and should be kept up-to-date with
// the latest api.PodStatus. It also syncs updates back to the API server.
type Manager interface {
	// Start the API server status sync loop.
	Start()

	// GetPodStatus returns the cached status for the provided pod UID, as well as whether it
	// was a cache hit.
	GetPodStatus(uid types.UID) (api.PodStatus, bool)

	// SetPodStatus caches updates the cached status for the given pod, and triggers a status update.
	SetPodStatus(pod *api.Pod, status api.PodStatus)

	// SetContainerReadiness updates the cached container status with the given readiness, and
	// triggers a status update.
	SetContainerReadiness(pod *api.Pod, containerID kubecontainer.ContainerID, ready bool)

	// TerminatePods resets the container status for the provided pods to terminated and triggers
	// a status update. This function may not enqueue all the provided pods, in which case it will
	// return false
	TerminatePods(pods []*api.Pod) bool

	// RemoveOrphanedStatuses scans the status cache and removes any entries for pods not included in
	// the provided podUIDs.
	RemoveOrphanedStatuses(podUIDs map[types.UID]bool)
}

const syncPeriod = 10 * time.Second

func NewManager(kubeClient client.Interface, podManager kubepod.Manager) Manager {
	return &manager{
		kubeClient:        kubeClient,
		podManager:        podManager,
		podStatuses:       make(map[types.UID]versionedPodStatus),
		podStatusChannel:  make(chan podStatusSyncRequest, 1000), // Buffer up to 1000 statuses
		apiStatusVersions: make(map[types.UID]uint64),
	}
}

// isStatusEqual returns true if the given pod statuses are equal, false otherwise.
// This method sorts container statuses so order does not affect equality.
func isStatusEqual(oldStatus, status *api.PodStatus) bool {
	sort.Sort(kubetypes.SortedContainerStatuses(status.ContainerStatuses))
	sort.Sort(kubetypes.SortedContainerStatuses(oldStatus.ContainerStatuses))

	// TODO: More sophisticated equality checking.
	return reflect.DeepEqual(status, oldStatus)
}

func (m *manager) Start() {
	// Don't start the status manager if we don't have a client. This will happen
	// on the master, where the kubelet is responsible for bootstrapping the pods
	// of the master components.
	if m.kubeClient == nil {
		glog.Infof("Kubernetes client is nil, not starting status manager.")
		return
	}

	glog.Info("Starting to sync pod status with apiserver")
	syncTicker := time.Tick(syncPeriod)
	// syncPod and syncBatch share the same go routine to avoid sync races.
	go util.Forever(func() {
		select {
		case syncRequest := <-m.podStatusChannel:
			m.syncPod(syncRequest.podUID, syncRequest.status)
		case <-syncTicker:
			m.syncBatch()
		}
	}, 0)
}

func (m *manager) GetPodStatus(uid types.UID) (api.PodStatus, bool) {
	m.podStatusesLock.RLock()
	defer m.podStatusesLock.RUnlock()
	status, ok := m.podStatuses[m.podManager.TranslatePodUID(uid)]
	return status.status, ok
}

func (m *manager) SetPodStatus(pod *api.Pod, status api.PodStatus) {
	m.podStatusesLock.Lock()
	defer m.podStatusesLock.Unlock()

	m.updateStatusInternal(pod, status, false)
}

func (m *manager) SetContainerReadiness(pod *api.Pod, containerID kubecontainer.ContainerID, ready bool) {
	m.podStatusesLock.Lock()
	defer m.podStatusesLock.Unlock()

	oldStatus, found := m.podStatuses[pod.UID]
	if !found {
		glog.Warningf("Container readiness changed before pod has synced: %q - %q",
			format.Pod(pod), containerID.String())
		return
	}

	// Find the container to update.
	containerIndex := -1
	for i, c := range oldStatus.status.ContainerStatuses {
		if c.ContainerID == containerID.String() {
			containerIndex = i
			break
		}
	}
	if containerIndex == -1 {
		glog.Warningf("Container readiness changed for unknown container: %q - %q",
			format.Pod(pod), containerID.String())
		return
	}

	if oldStatus.status.ContainerStatuses[containerIndex].Ready == ready {
		glog.V(4).Infof("Container readiness unchanged (%v): %q - %q", ready,
			format.Pod(pod), containerID.String())
		return
	}

	// Make sure we're not updating the cached version.
	clone, err := api.Scheme.DeepCopy(&oldStatus.status)
	if err != nil {
		glog.Errorf("Failed to clone status %+v: %v", oldStatus.status, err)
		return
	}
	status := *clone.(*api.PodStatus)
	status.ContainerStatuses[containerIndex].Ready = ready

	// Update pod condition.
	readyConditionIndex := -1
	for i, condition := range status.Conditions {
		if condition.Type == api.PodReady {
			readyConditionIndex = i
			break
		}
	}
	readyCondition := GeneratePodReadyCondition(&pod.Spec, status.ContainerStatuses, status.Phase)
	if readyConditionIndex != -1 {
		status.Conditions[readyConditionIndex] = readyCondition
	} else {
		glog.Warningf("PodStatus missing PodReady condition: %+v", status)
		status.Conditions = append(status.Conditions, readyCondition)
	}

	m.updateStatusInternal(pod, status, false)
}

func (m *manager) TerminatePods(pods []*api.Pod) bool {
	allSent := true
	m.podStatusesLock.Lock()
	defer m.podStatusesLock.Unlock()
	for _, pod := range pods {
		if sent := m.updateStatusInternal(pod, api.PodStatus{}, true); !sent {
			glog.V(4).Infof("Termination notice for %q was dropped because the status channel is full", format.Pod(pod))
			allSent = false
		}
	}
	return allSent
}

// updateStatusInternal updates the internal status cache, and queues an update to the api server if
// necessary. Returns whether an update was triggered.
// This method IS NOT THREAD SAFE and must be called from a locked function.
func (m *manager) updateStatusInternal(pod *api.Pod, status api.PodStatus, forceUpdate bool) bool {
	var oldStatus api.PodStatus
	cachedStatus, isCached := m.podStatuses[pod.UID]
	if isCached {
		oldStatus = cachedStatus.status
	} else if mirrorPod, ok := m.podManager.GetMirrorPodByPod(pod); ok {
		oldStatus = mirrorPod.Status
	} else {
		oldStatus = pod.Status
	}

	if forceUpdate {
		status = oldStatus
	} else {
		// Set ReadyCondition.LastTransitionTime.
		if readyCondition := api.GetPodReadyCondition(status); readyCondition != nil {
			// Need to set LastTransitionTime.
			lastTransitionTime := unversioned.Now()
			oldReadyCondition := api.GetPodReadyCondition(oldStatus)
			if oldReadyCondition != nil && readyCondition.Status == oldReadyCondition.Status {
				lastTransitionTime = oldReadyCondition.LastTransitionTime
			}
			readyCondition.LastTransitionTime = lastTransitionTime
		}

		// ensure that the start time does not change across updates.
		if oldStatus.StartTime != nil && !oldStatus.StartTime.IsZero() {
			status.StartTime = oldStatus.StartTime
		} else if status.StartTime.IsZero() {
			// if the status has no start time, we need to set an initial time
			now := unversioned.Now()
			status.StartTime = &now
		}
		// The intent here is to prevent concurrent updates to a pod's status from
		// clobbering each other so the phase of a pod progresses monotonically.
		if isCached && isStatusEqual(&cachedStatus.status, &status) {
			glog.V(3).Infof("Ignoring same status for pod %q, status: %+v", format.Pod(pod), status)
			return false // No new status.
		}
	}

	newStatus := versionedPodStatus{
		status:       status,
		version:      cachedStatus.version + 1,
		podName:      pod.Name,
		podNamespace: pod.Namespace,
	}
	m.podStatuses[pod.UID] = newStatus

	select {
	case m.podStatusChannel <- podStatusSyncRequest{pod.UID, newStatus}:
		return true
	default:
		// Let the periodic syncBatch handle the update if the channel is full.
		// We can't block, since we hold the mutex lock.
		return false
	}
}

// deletePodStatus simply removes the given pod from the status cache.
func (m *manager) deletePodStatus(uid types.UID) {
	m.podStatusesLock.Lock()
	defer m.podStatusesLock.Unlock()
	delete(m.podStatuses, uid)
}

// TODO(filipg): It'd be cleaner if we can do this without signal from user.
func (m *manager) RemoveOrphanedStatuses(podUIDs map[types.UID]bool) {
	m.podStatusesLock.Lock()
	defer m.podStatusesLock.Unlock()
	for key := range m.podStatuses {
		if _, ok := podUIDs[key]; !ok {
			glog.V(5).Infof("Removing %q from status map.", key)
			delete(m.podStatuses, key)
		}
	}
}

// syncBatch syncs pods statuses with the apiserver.
func (m *manager) syncBatch() {
	var updatedStatuses []podStatusSyncRequest
	podToMirror, mirrorToPod := m.podManager.GetUIDTranslations()
	func() { // Critical section
		m.podStatusesLock.RLock()
		defer m.podStatusesLock.RUnlock()

		// Clean up orphaned versions.
		for uid := range m.apiStatusVersions {
			_, hasPod := m.podStatuses[uid]
			_, hasMirror := mirrorToPod[uid]
			if !hasPod && !hasMirror {
				delete(m.apiStatusVersions, uid)
			}
		}

		for uid, status := range m.podStatuses {
			syncedUID := uid
			if mirrorUID, ok := podToMirror[uid]; ok {
				syncedUID = mirrorUID
			}
			if m.needsUpdate(syncedUID, status) {
				updatedStatuses = append(updatedStatuses, podStatusSyncRequest{uid, status})
			}
		}
	}()

	for _, update := range updatedStatuses {
		m.syncPod(update.podUID, update.status)
	}
}

// syncPod syncs the given status with the API server. The caller must not hold the lock.
func (m *manager) syncPod(uid types.UID, status versionedPodStatus) {
	// TODO: make me easier to express from client code
	pod, err := m.kubeClient.Pods(status.podNamespace).Get(status.podName)
	if errors.IsNotFound(err) {
		glog.V(3).Infof("Pod %q (%s) does not exist on the server", status.podName, uid)
		// If the Pod is deleted the status will be cleared in
		// RemoveOrphanedStatuses, so we just ignore the update here.
		return
	}
	if err == nil {
		translatedUID := m.podManager.TranslatePodUID(pod.UID)
		if len(translatedUID) > 0 && translatedUID != uid {
			glog.V(3).Infof("Pod %q was deleted and then recreated, skipping status update", format.Pod(pod))
			m.deletePodStatus(uid)
			return
		}
		if !m.needsUpdate(pod.UID, status) {
			glog.V(1).Infof("Status for pod %q is up-to-date; skipping", format.Pod(pod))
			return
		}
		pod.Status = status.status
		// TODO: handle conflict as a retry, make that easier too.
		pod, err = m.kubeClient.Pods(pod.Namespace).UpdateStatus(pod)
		if err == nil {
			glog.V(3).Infof("Status for pod %q updated successfully: %+v", format.Pod(pod), status)
			m.apiStatusVersions[pod.UID] = status.version

			if pod.DeletionTimestamp == nil {
				return
			}
			if !notRunning(pod.Status.ContainerStatuses) {
				glog.V(3).Infof("Pod %q is terminated, but some containers are still running", format.Pod(pod))
				return
			}
			if err := m.kubeClient.Pods(pod.Namespace).Delete(pod.Name, api.NewDeleteOptions(0)); err == nil {
				glog.V(3).Infof("Pod %q fully terminated and removed from etcd", format.Pod(pod))
				m.deletePodStatus(uid)
				return
			}
		}
	}

	// We failed to update status, wait for periodic sync to retry.
	glog.Warningf("Failed to update status for pod %q: %v", format.Pod(pod), err)
}

// needsUpdate returns whether the status is stale for the given pod UID.
// This method is not thread safe, and most only be accessed by the sync thread.
func (m *manager) needsUpdate(uid types.UID, status versionedPodStatus) bool {
	latest, ok := m.apiStatusVersions[uid]
	return !ok || latest < status.version
}

// notRunning returns true if every status is terminated or waiting, or the status list
// is empty.
func notRunning(statuses []api.ContainerStatus) bool {
	for _, status := range statuses {
		if status.State.Terminated == nil && status.State.Waiting == nil {
			return false
		}
	}
	return true
}
