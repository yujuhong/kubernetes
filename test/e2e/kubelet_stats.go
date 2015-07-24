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

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/GoogleCloudPlatform/kubernetes/pkg/api"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/client"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/fields"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/kubelet"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/kubelet/metrics"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/labels"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/master/ports"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/util"
	"github.com/GoogleCloudPlatform/kubernetes/test/e2e/cirbuf"
	cadvisor "github.com/google/cadvisor/info/v1"
)

// KubeletMetric stores metrics scraped from the kubelet server's /metric endpoint.
// TODO: Get some more structure aroud the metrics and this type
type KubeletMetric struct {
	// eg: list, info, create
	Operation string
	// eg: sync_pods, pod_worker
	Method string
	// 0 <= quantile <=1, e.g. 0.95 is 95%tile, 0.5 is median.
	Quantile float64
	Latency  time.Duration
}

// KubeletMetricByLatency implements sort.Interface for []KubeletMetric based on
// the latency field.
type KubeletMetricByLatency []KubeletMetric

func (a KubeletMetricByLatency) Len() int           { return len(a) }
func (a KubeletMetricByLatency) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a KubeletMetricByLatency) Less(i, j int) bool { return a[i].Latency > a[j].Latency }

// ReadKubeletMetrics reads metrics from the kubelet server running on the given node
func ParseKubeletMetrics(metricsBlob string) ([]KubeletMetric, error) {
	metric := make([]KubeletMetric, 0)
	for _, line := range strings.Split(metricsBlob, "\n") {

		// A kubelet stats line starts with the KubeletSubsystem marker, followed by a stat name, followed by fields
		// that vary by stat described on a case by case basis below.
		// TODO: String parsing is such a hack, but getting our rest client/proxy to cooperate with prometheus
		// client is weird, we should eventually invest some time in doing this the right way.
		if !strings.HasPrefix(line, fmt.Sprintf("%v_", metrics.KubeletSubsystem)) {
			continue
		}
		keyVal := strings.Split(line, " ")
		if len(keyVal) != 2 {
			return nil, fmt.Errorf("Error parsing metric %q", line)
		}
		keyElems := strings.Split(line, "\"")

		latency, err := strconv.ParseFloat(keyVal[1], 64)
		if err != nil {
			continue
		}

		methodLine := strings.Split(keyElems[0], "{")
		methodList := strings.Split(methodLine[0], "_")
		if len(methodLine) != 2 || len(methodList) == 1 {
			continue
		}
		method := strings.Join(methodList[1:], "_")

		var operation, rawQuantile string
		var quantile float64

		switch method {
		case metrics.PodWorkerLatencyKey:
			// eg: kubelet_pod_worker_latency_microseconds{operation_type="create",pod_name="foopause3_default",quantile="0.99"} 1344
			if len(keyElems) != 7 {
				continue
			}
			operation = keyElems[1]
			rawQuantile = keyElems[5]
			break

		case metrics.PodWorkerStartLatencyKey:
			// eg: kubelet_pod_worker_start_latency_microseconds{quantile="0.99"} 12
			fallthrough

		case metrics.SyncPodsLatencyKey:
			// eg:  kubelet_sync_pods_latency_microseconds{quantile="0.5"} 9949
			fallthrough

		case metrics.PodStartLatencyKey:
			// eg: kubelet_pod_start_latency_microseconds{quantile="0.5"} 123
			fallthrough

		case metrics.PodStatusLatencyKey:
			// eg: kubelet_generate_pod_status_latency_microseconds{quantile="0.5"} 12715
			if len(keyElems) != 3 {
				continue
			}
			operation = ""
			rawQuantile = keyElems[1]
			break

		case metrics.ContainerManagerOperationsKey:
			// eg: kubelet_container_manager_latency_microseconds{operation_type="SyncPod",quantile="0.5"} 6705
			fallthrough

		case metrics.DockerOperationsKey:
			// eg: kubelet_docker_operations_latency_microseconds{operation_type="info",quantile="0.5"} 31590
			if len(keyElems) != 5 {
				continue
			}
			operation = keyElems[1]
			rawQuantile = keyElems[3]
			break

		case metrics.DockerErrorsKey:
			Logf("ERROR %v", line)

		default:
			continue
		}
		quantile, err = strconv.ParseFloat(rawQuantile, 64)
		if err != nil {
			continue
		}
		metric = append(metric, KubeletMetric{operation, method, quantile, time.Duration(int64(latency)) * time.Microsecond})
	}
	return metric, nil
}

// HighLatencyKubeletOperations logs and counts the high latency metrics exported by the kubelet server via /metrics.
func HighLatencyKubeletOperations(c *client.Client, threshold time.Duration, nodeName string) ([]KubeletMetric, error) {
	var metricsBlob string
	var err error
	// If we haven't been given a client try scraping the nodename directly for a /metrics endpoint.
	if c == nil {
		metricsBlob, err = getKubeletMetricsThroughNode(nodeName)
	} else {
		metricsBlob, err = getKubeletMetricsThroughProxy(c, nodeName)
	}
	if err != nil {
		return []KubeletMetric{}, err
	}
	metric, err := ParseKubeletMetrics(metricsBlob)
	if err != nil {
		return []KubeletMetric{}, err
	}
	sort.Sort(KubeletMetricByLatency(metric))
	var badMetrics []KubeletMetric
	Logf("\nLatency metrics for node %v", nodeName)
	for _, m := range metric {
		if m.Latency > threshold {
			badMetrics = append(badMetrics, m)
			Logf("%+v", m)
		}
	}
	return badMetrics, nil
}

// getContainerInfo contacts kubelet for the container informaton. The "Stats"
// in the returned ContainerInfo is subject to the requirements in statsRequest.
func getContainerInfo(c *client.Client, nodeName string, req *kubelet.StatsRequest) (map[string]cadvisor.ContainerInfo, error) {
	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	data, err := c.Post().
		Prefix("proxy").
		Resource("nodes").
		Name(fmt.Sprintf("%v:%v", nodeName, ports.KubeletPort)).
		Suffix("stats/container").
		SetHeader("Content-Type", "application/json").
		Body(reqBody).
		Do().Raw()

	var containers map[string]cadvisor.ContainerInfo
	err = json.Unmarshal(data, &containers)
	if err != nil {
		return nil, err
	}
	return containers, nil
}

const (
	// cadvisor records stats about every second.
	cadvisorStatsPollingIntervalInSeconds float64 = 1.0
	// cadvisor caches up to 2 minutes of stats (configured by kubelet).
	maxNumStatsToRequest int = 120
)

// A list of containers for which we want to collect resource usage.
var targetContainers = []string{
	"/",
	"/docker-daemon",
	"/kubelet",
	"/kube-proxy",
	"/system",
}

type containerResourceUsage struct {
	Name                    string
	Timestamp               time.Time
	CPUUsageInCores         float64
	MemoryUsageInBytes      int64
	MemoryWorkingSetInBytes int64
	// The interval used to calculate CPUUsageInCores.
	CPUInterval time.Duration
}

// getOneTimeResourceUsageOnNode queries the node's /stats/container endpoint
// and returns the resource usage of targetContainers for the past
// cpuInterval.
// The acceptable range of the interval is 2s~120s. Be warned that as the
// interval (and #containers) increases, the size of kubelet's response
// could be sigificant. E.g., the 60s interval stats for ~20 containers is
// ~1.5MB. Don't hammer the node with frequent, heavy requests.
//
// cadvisor records cumulative cpu usage in nanoseconds, so we need to have two
// stats points to compute the cpu usage over the interval. Assuming cadvisor
// polls every second, we'd need to get N stats points for N-second interval.
// Note that this is an approximation and may not be accurate, hence we also
// write the actual interval used for calcuation (based on the timestampes of
// the stats points in containerResourceUsage.CPUInterval.
func getOneTimeResourceUsageOnNode(c *client.Client, nodeName string, cpuInterval time.Duration) (map[string]*containerResourceUsage, error) {
	numStats := int(float64(cpuInterval.Seconds()) / cadvisorStatsPollingIntervalInSeconds)
	if numStats < 2 || numStats > maxNumStatsToRequest {
		return nil, fmt.Errorf("numStats needs to be > 1 and < %d", maxNumStatsToRequest)
	}
	// Get information of all containers on the node.
	containerInfos, err := getContainerInfo(c, nodeName, &kubelet.StatsRequest{
		ContainerName: "/",
		NumStats:      numStats,
		Subcontainers: true,
	})
	if err != nil {
		return nil, err
	}
	// Process container infos that are relevant to us.
	usageMap := make(map[string]*containerResourceUsage, len(targetContainers))
	for _, name := range targetContainers {
		info, ok := containerInfos[name]
		if !ok {
			return nil, fmt.Errorf("missing info for container %q on node %q", name, nodeName)
		}
		first := info.Stats[0]
		last := info.Stats[len(info.Stats)-1]
		usageMap[name] = computeContainerResourceUsage(name, first, last)
	}
	return usageMap, nil
}

// logOneTimeResourceUsageSummary collects container resource for the list of
// nodes, formats and logs the stats.
func logOneTimeResourceUsageSummary(c *client.Client, nodeNames []string, cpuInterval time.Duration) {
	var summary []string
	for _, nodeName := range nodeNames {
		stats, err := getOneTimeResourceUsageOnNode(c, nodeName, cpuInterval)
		if err != nil {
			summary = append(summary, fmt.Sprintf("Error getting resource usage from node %q, err: %v", nodeName, err))
		} else {
			summary = append(summary, formatResourceUsageStats(nodeName, stats))
		}
	}
	Logf("\n%s", strings.Join(summary, "\n"))
}

func formatResourceUsageStats(nodeName string, containerStats map[string]*containerResourceUsage) string {
	// Example output:
	//
	// Resource usage for node "e2e-test-foo-minion-abcde":
	// container        cpu(cores)  memory(MB)
	// "/"              0.363       2942.09
	// "/docker-daemon" 0.088       521.80
	// "/kubelet"       0.086       424.37
	// "/kube-proxy"    0.011       4.66
	// "/system"        0.007       119.88
	buf := &bytes.Buffer{}
	w := tabwriter.NewWriter(buf, 1, 0, 1, ' ', 0)
	fmt.Fprintf(w, "container\tcpu(cores)\tmemory(MB)\n")
	for name, s := range containerStats {
		fmt.Fprintf(w, "%q\t%.3f\t%.2f\n", name, s.CPUUsageInCores, float64(s.MemoryUsageInBytes)/1000000)
	}
	w.Flush()
	return fmt.Sprintf("Resource usage on node %q:\n%s", nodeName, buf.String())
}

// Performs a get on a node proxy endpoint given the nodename and rest client.
func nodeProxyRequest(c *client.Client, node, endpoint string) client.Result {
	return c.Get().
		Prefix("proxy").
		Resource("nodes").
		Name(fmt.Sprintf("%v:%v", node, ports.KubeletPort)).
		Suffix(endpoint).
		Do()
}

// Retrieve metrics from the kubelet server of the given node.
func getKubeletMetricsThroughProxy(c *client.Client, node string) (string, error) {
	metric, err := nodeProxyRequest(c, node, "metrics").Raw()
	if err != nil {
		return "", err
	}
	return string(metric), nil
}

// Retrieve metrics from the kubelet on the given node using a simple GET over http.
// Currently only used in integration tests.
func getKubeletMetricsThroughNode(nodeName string) (string, error) {
	resp, err := http.Get(fmt.Sprintf("http://%v/metrics", nodeName))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// GetKubeletPods retrieves the list of running pods on the kubelet. The pods
// includes necessary information (e.g., UID, name, namespace for
// pods/containers), but do not contain the full spec.
func GetKubeletPods(c *client.Client, node string) (*api.PodList, error) {
	result := &api.PodList{}
	if err := nodeProxyRequest(c, node, "runningpods").Into(result); err != nil {
		return &api.PodList{}, err
	}
	return result, nil
}

func computeContainerResourceUsage(name string, oldStats, newStats *cadvisor.ContainerStats) *containerResourceUsage {
	return &containerResourceUsage{
		Name:                    name,
		Timestamp:               newStats.Timestamp,
		CPUUsageInCores:         float64(newStats.Cpu.Usage.Total-oldStats.Cpu.Usage.Total) / float64(newStats.Timestamp.Sub(oldStats.Timestamp).Nanoseconds()),
		MemoryUsageInBytes:      int64(newStats.Memory.Usage),
		MemoryWorkingSetInBytes: int64(newStats.Memory.WorkingSet),
		CPUInterval:             newStats.Timestamp.Sub(oldStats.Timestamp),
	}
}

// resourceCollector periodically polls the node, collect stats for a given
// list of containers, computes and cache resource usage up to
// maxEntriesPerContainer for each container.
type resourceCollector struct {
	node            string
	containers      []string
	client          *client.Client
	buffers         map[string]*cirbuf.CircularBuffer
	pollingInterval time.Duration
	stopCh          chan struct{}
}

func newResourceCollector(c *client.Client, nodeName string, containerNames []string, maxEntriesPerContainer int, pollingInterval time.Duration) *resourceCollector {
	buffers := make(map[string]*cirbuf.CircularBuffer, 0)
	for _, name := range containerNames {
		buffers[name] = cirbuf.NewCircularBuffer(maxEntriesPerContainer)
	}
	return &resourceCollector{
		node:            nodeName,
		containers:      containerNames,
		client:          c,
		buffers:         buffers,
		pollingInterval: pollingInterval,
	}
}

// Start starts a goroutine to poll the node every pollingInerval.
func (r *resourceCollector) Start() {
	r.stopCh = make(chan struct{}, 1)
	// Keep the last observed stats for comparison.
	oldStats := make(map[string]*cadvisor.ContainerStats)
	go util.Until(func() { r.collectStats(oldStats) }, r.pollingInterval, r.stopCh)
}

// Stop sends a signal to terminate the stats collecting goroutine.
func (r *resourceCollector) Stop() {
	close(r.stopCh)
}

// collectStats gets the latest stats from kubelet's /stats/container, computes
// the resource usage, and pushes it to the buffer.
func (r *resourceCollector) collectStats(oldStats map[string]*cadvisor.ContainerStats) {
	infos, err := getContainerInfo(r.client, r.node, &kubelet.StatsRequest{
		ContainerName: "/",
		NumStats:      1,
		Subcontainers: true,
	})
	if err != nil {
		Logf("Error getting container info on %q, err: %v", r.node, err)
		return
	}
	for _, name := range r.containers {
		info, ok := infos[name]
		if !ok || len(info.Stats) < 1 {
			Logf("Missing info/stats for container %q on node %q", name, r.node)
			return
		}
		if _, ok := oldStats[name]; ok {
			r.buffers[name].Push(computeContainerResourceUsage(name, oldStats[name], info.Stats[0]))
		}
		oldStats[name] = info.Stats[0]
	}
}

// LogLatest logs the latest resource usage of each container.
func (r *resourceCollector) LogLatest() {
	stats := make(map[string]*containerResourceUsage)
	for _, name := range r.containers {
		s := r.buffers[name].GetLatest()
		if s == nil {
			Logf("Resource usage on node %q is not ready yet", r.node)
			return
		}
		stats[name] = s.(*containerResourceUsage)
	}
	Logf("\n%s", formatResourceUsageStats(r.node, stats))
}

// GetBasicCPUStats returns the min, max, and average of the cpu usage in cores
// for containerName. This method examines all data currently in the buffer.
func (r *resourceCollector) GetBasicCPUStats(containerName string) (float64, float64, float64) {
	var min, max, sum float64
	usages := r.buffers[containerName].List()
	for i := range usages {
		u := usages[i].(*containerResourceUsage)
		sum += u.CPUUsageInCores
		if i == 0 {
			max = min
			sum = min
			continue
		}
		if u.CPUUsageInCores < min {
			min = u.CPUUsageInCores
		}
		if u.CPUUsageInCores > max {
			max = u.CPUUsageInCores
		}
	}
	return min, max, sum / float64(len(usages))
}

// resourceMonitor manages a resourceCollector per node.
type resourceMonitor struct {
	client                 *client.Client
	containers             []string
	pollingInterval        time.Duration
	maxEntriesPerContainer int
	collectors             map[string]*resourceCollector
}

func newResourceMonitor(c *client.Client, containerNames []string, maxEntriesPerContainer int, pollingInterval time.Duration) *resourceMonitor {
	return &resourceMonitor{
		containers:             containerNames,
		client:                 c,
		pollingInterval:        pollingInterval,
		maxEntriesPerContainer: maxEntriesPerContainer,
	}
}

func (r *resourceMonitor) Start() {
	nodes, err := r.client.Nodes().List(labels.Everything(), fields.Everything())
	if err != nil {
		Failf("resourceMonitor: unable to get list of nodes: %v", err)
	}
	r.collectors = make(map[string]*resourceCollector, 0)
	for _, node := range nodes.Items {
		collector := newResourceCollector(r.client, node.Name, r.containers, maxEntriesPerContainer, pollInterval)
		r.collectors[node.Name] = collector
		collector.Start()
	}
}

func (r *resourceMonitor) Stop() {
	for _, collector := range r.collectors {
		collector.Stop()
	}
}

func (r *resourceMonitor) LogLatest() {
	for _, collector := range r.collectors {
		collector.LogLatest()
	}
}

func (r *resourceMonitor) LogCPUSummary(containerName string) {
	for name, collector := range r.collectors {
		min, max, avg := collector.GetBasicCPUStats(containerName)
		Logf("cpu usage summary of container %q on node %q: min %.3f, max %.3f, avg %.3f",
			containerName, name, min, max, avg)
	}
}
