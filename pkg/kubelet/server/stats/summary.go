/*
Copyright 2016 The Kubernetes Authors All rights reserved.

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

package stats

import (
	"fmt"
	"time"

	"github.com/golang/glog"
	cadvisorapiv1 "github.com/google/cadvisor/info/v1"
	cadvisorapiv2 "github.com/google/cadvisor/info/v2"
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/api/unversioned"
	"k8s.io/kubernetes/pkg/kubelet/cm"
	"k8s.io/kubernetes/pkg/kubelet/dockertools"
	"k8s.io/kubernetes/pkg/kubelet/leaky"
)

type SummaryProvider interface {
	// Get provides a new Summary using the latest results from cadvisor
	Get() (*Summary, error)
}

type summaryProviderImpl struct {
	provider StatsProvider
}

var _ SummaryProvider = &summaryProviderImpl{}

// NewSummaryProvider returns a new SummaryProvider
func NewSummaryProvider(statsProvider StatsProvider) SummaryProvider {
	return &summaryProviderImpl{statsProvider}
}

// Get implements the SummaryProvider interface
// Query cadvisor for the latest resource metrics and build into a summary
func (sp *summaryProviderImpl) Get() (*Summary, error) {
	options := cadvisorapiv2.RequestOptions{
		IdType:    cadvisorapiv2.TypeName,
		Count:     2, // 2 samples are needed to compute "instantaneous" CPU
		Recursive: true,
	}
	infos, err := sp.provider.GetContainerInfoV2("/", options)
	if err != nil {
		return nil, err
	}

	node, err := sp.provider.GetNode()
	if err != nil {
		return nil, err
	}

	nodeConfig := sp.provider.GetNodeConfig()
	rootFsInfo, err := sp.provider.RootFsInfo()
	if err != nil {
		return nil, err
	}
	imageFsInfo, err := sp.provider.DockerImagesFsInfo()
	if err != nil {
		return nil, err
	}

	sb := &summaryBuilder{node, nodeConfig, rootFsInfo, imageFsInfo, infos}
	return sb.build()
}

// summaryBuilder aggregates the datastructures provided by cadvisor into a Summary result
type summaryBuilder struct {
	node        *api.Node
	nodeConfig  cm.NodeConfig
	rootFsInfo  cadvisorapiv2.FsInfo
	imageFsInfo cadvisorapiv2.FsInfo
	infos       map[string]cadvisorapiv2.ContainerInfo
}

// build returns a Summary from aggregating the input data
func (sb *summaryBuilder) build() (*Summary, error) {
	rootInfo, found := sb.infos["/"]
	if !found {
		return nil, fmt.Errorf("Missing stats for root container")
	}
	cstat, found := sb.latestContainerStats(&rootInfo)
	if !found {
		return nil, fmt.Errorf("Missing stats for root container")
	}

	rootStats := sb.containerInfoV2ToStats("", &rootInfo)
	nodeStats := NodeStats{
		NodeName: sb.node.Name,
		CPU:      rootStats.CPU,
		Memory:   rootStats.Memory,
		Network:  sb.containerInfoV2ToNetworkStats(&rootInfo),
		Fs: &FsStats{
			AvailableBytes: &sb.rootFsInfo.Available,
			CapacityBytes:  &sb.rootFsInfo.Capacity,
			UsedBytes:      &sb.rootFsInfo.Usage},
		StartTime: rootStats.StartTime,
	}

	systemContainers := map[string]string{
		SystemContainerKubelet: sb.nodeConfig.KubeletContainerName,
		SystemContainerRuntime: sb.nodeConfig.DockerDaemonContainerName, // TODO: add support for other runtimes
		SystemContainerMisc:    sb.nodeConfig.SystemContainerName,
	}
	for sys, name := range systemContainers {
		if info, ok := sb.infos[name]; ok {
			nodeStats.SystemContainers = append(nodeStats.SystemContainers, sb.containerInfoV2ToStats(sys, &info))
		}
	}

	summary := Summary{
		Time: unversioned.NewTime(cstat.Timestamp),
		Node: nodeStats,
		Pods: sb.buildSummaryPods(),
	}
	return &summary, nil
}

// containerInfoV2FsStats populates the container fs stats
func (sb *summaryBuilder) containerInfoV2FsStats(
	info *cadvisorapiv2.ContainerInfo,
	cs *ContainerStats) {

	// The container logs live on the node rootfs device
	cs.Logs = &FsStats{
		AvailableBytes: &sb.rootFsInfo.Available,
		CapacityBytes:  &sb.rootFsInfo.Capacity,
	}

	// The container rootFs lives on the imageFs devices (which may not be the node root fs)
	cs.Rootfs = &FsStats{
		AvailableBytes: &sb.imageFsInfo.Available,
		CapacityBytes:  &sb.imageFsInfo.Capacity,
	}

	lcs, found := sb.latestContainerStats(info)
	if !found {
		return
	}
	cfs := lcs.Filesystem
	if cfs != nil && cfs.BaseUsageBytes != nil {
		cs.Rootfs.UsedBytes = cfs.BaseUsageBytes
		if cfs.TotalUsageBytes != nil {
			logsUsage := *cfs.TotalUsageBytes - *cfs.BaseUsageBytes
			cs.Logs.UsedBytes = &logsUsage
		}
	}
}

// latestContainerStats returns the latest container stats from cadvisor, or nil if none exist
func (sb *summaryBuilder) latestContainerStats(info *cadvisorapiv2.ContainerInfo) (*cadvisorapiv2.ContainerStats, bool) {
	stats := info.Stats
	if len(stats) < 1 {
		return nil, false
	}
	latest := stats[len(stats)-1]
	if latest == nil {
		return nil, false
	}
	return latest, true
}

// buildSummaryPods aggregates and returns the container stats in cinfos by the Pod managing the container.
// Containers not managed by a Pod are omitted.
func (sb *summaryBuilder) buildSummaryPods() []PodStats {
	// Map each container to a pod and update the PodStats with container data
	podToStats := map[PodReference]*PodStats{}
	for _, cinfo := range sb.infos {
		// Build the Pod key if this container is managed by a Pod
		if !sb.isPodManagedContainer(&cinfo) {
			continue
		}
		ref := sb.buildPodRef(&cinfo)

		// Lookup the PodStats for the pod using the PodRef.  If none exists, initialize a new entry.
		stats, found := podToStats[ref]
		if !found {
			stats = &PodStats{PodRef: ref}
			podToStats[ref] = stats
		}

		// Update the PodStats entry with the stats from the container by adding it to stats.Containers
		containerName := dockertools.GetContainerName(cinfo.Spec.Labels)
		if containerName == leaky.PodInfraContainerName {
			// Special case for infrastructure container which is hidden from the user and has network stats
			stats.Network = sb.containerInfoV2ToNetworkStats(&cinfo)
			stats.StartTime = unversioned.NewTime(cinfo.Spec.CreationTime)
		} else {
			stats.Containers = append(stats.Containers, sb.containerInfoV2ToStats(containerName, &cinfo))
		}
	}

	// Add each PodStats to the result
	result := make([]PodStats, 0, len(podToStats))
	for _, stats := range podToStats {
		result = append(result, *stats)
	}
	return result
}

// buildPodRef returns a PodReference that identifies the Pod managing cinfo
func (sb *summaryBuilder) buildPodRef(cinfo *cadvisorapiv2.ContainerInfo) PodReference {
	podName := dockertools.GetPodName(cinfo.Spec.Labels)
	podNamespace := dockertools.GetPodNamespace(cinfo.Spec.Labels)
	podUID := dockertools.GetPodUID(cinfo.Spec.Labels)
	return PodReference{Name: podName, Namespace: podNamespace, UID: podUID}
}

// isPodManagedContainer returns true if the cinfo container is managed by a Pod
func (sb *summaryBuilder) isPodManagedContainer(cinfo *cadvisorapiv2.ContainerInfo) bool {
	podName := dockertools.GetPodName(cinfo.Spec.Labels)
	podNamespace := dockertools.GetPodNamespace(cinfo.Spec.Labels)
	managed := podName != "" && podNamespace != ""
	if !managed && podName != podNamespace {
		glog.Warningf(
			"Expect container to have either both podName (%s) and podNamespace (%s) labels, or neither.",
			podName, podNamespace)
	}
	return managed
}

func (sb *summaryBuilder) containerInfoV2ToStats(
	name string,
	info *cadvisorapiv2.ContainerInfo) ContainerStats {
	stats := ContainerStats{
		Name:      name,
		StartTime: unversioned.NewTime(info.Spec.CreationTime),
	}
	cstat, found := sb.latestContainerStats(info)
	if !found {
		return stats
	}
	if info.Spec.HasCpu {
		cpuStats := CPUStats{}
		if cstat.CpuInst != nil {
			cpuStats.UsageNanoCores = &cstat.CpuInst.Usage.Total
		}
		if cstat.Cpu != nil {
			cpuStats.UsageCoreNanoSeconds = &cstat.Cpu.Usage.Total
		}
		stats.CPU = &cpuStats
	}
	if info.Spec.HasMemory {
		pageFaults := cstat.Memory.ContainerData.Pgfault
		majorPageFaults := cstat.Memory.ContainerData.Pgmajfault
		stats.Memory = &MemoryStats{
			UsageBytes:      &cstat.Memory.Usage,
			WorkingSetBytes: &cstat.Memory.WorkingSet,
			PageFaults:      &pageFaults,
			MajorPageFaults: &majorPageFaults,
		}
	}
	sb.containerInfoV2FsStats(info, &stats)
	stats.UserDefinedMetrics = sb.containerInfoV2ToUserDefinedMetrics(info)
	return stats
}

func (sb *summaryBuilder) containerInfoV2ToNetworkStats(info *cadvisorapiv2.ContainerInfo) *NetworkStats {
	if !info.Spec.HasNetwork {
		return nil
	}
	cstat, found := sb.latestContainerStats(info)
	if !found {
		return nil
	}
	var (
		rxBytes  uint64
		rxErrors uint64
		txBytes  uint64
		txErrors uint64
	)
	// TODO(stclair): check for overflow
	for _, inter := range cstat.Network.Interfaces {
		rxBytes += inter.RxBytes
		rxErrors += inter.RxErrors
		txBytes += inter.TxBytes
		txErrors += inter.TxErrors
	}
	return &NetworkStats{
		RxBytes:  &rxBytes,
		RxErrors: &rxErrors,
		TxBytes:  &txBytes,
		TxErrors: &txErrors,
	}
}

func (sb *summaryBuilder) containerInfoV2ToUserDefinedMetrics(info *cadvisorapiv2.ContainerInfo) []UserDefinedMetric {
	type specVal struct {
		ref     UserDefinedMetricDescriptor
		valType cadvisorapiv1.DataType
		time    time.Time
		value   float64
	}
	udmMap := map[string]*specVal{}
	for _, spec := range info.Spec.CustomMetrics {
		udmMap[spec.Name] = &specVal{
			ref: UserDefinedMetricDescriptor{
				Name:  spec.Name,
				Type:  UserDefinedMetricType(spec.Type),
				Units: spec.Units,
			},
			valType: spec.Format,
		}
	}
	for _, stat := range info.Stats {
		for name, values := range stat.CustomMetrics {
			specVal, ok := udmMap[name]
			if !ok {
				glog.Warningf("spec for custom metric %q is missing from cAdvisor output. Spec: %+v, Metrics: %+v", name, info.Spec, stat.CustomMetrics)
				continue
			}
			for _, value := range values {
				// Pick the most recent value
				if value.Timestamp.Before(specVal.time) {
					continue
				}
				specVal.time = value.Timestamp
				specVal.value = value.FloatValue
				if specVal.valType == cadvisorapiv1.IntType {
					specVal.value = float64(value.IntValue)
				}
			}
		}
	}
	var udm []UserDefinedMetric
	for _, specVal := range udmMap {
		udm = append(udm, UserDefinedMetric{
			UserDefinedMetricDescriptor: specVal.ref,
			Value: specVal.value,
		})
	}
	return udm
}
