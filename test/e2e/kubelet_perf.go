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

package e2e

import (
	"fmt"
	"strings"
	"time"

	client "k8s.io/kubernetes/pkg/client/unversioned"
	"k8s.io/kubernetes/pkg/kubelet/api/v1alpha1/stats"
	"k8s.io/kubernetes/pkg/util"
	"k8s.io/kubernetes/pkg/util/sets"
	"k8s.io/kubernetes/test/e2e/framework"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

const (
	// Interval to poll /stats/container on a node
	containerStatsPollingPeriod = 10 * time.Second
	// The monitoring time for one test.
	monitoringTime = 20 * time.Minute
	// The periodic reporting period.
	reportingPeriod = 5 * time.Minute
)

type resourceTest struct {
	podsPerNode int
	cpuLimits   framework.ContainersCPUSummary
	memLimits   framework.ResourceUsagePerContainer
	// A list of containers to track on the node.
	containers []string
}

func logPodsOnNodes(c *client.Client, nodeNames []string) {
	for _, n := range nodeNames {
		podList, err := framework.GetKubeletRunningPods(c, n)
		if err != nil {
			framework.Logf("Unable to retrieve kubelet pods for node %v", n)
			continue
		}
		framework.Logf("%d pods are running on node %v", len(podList.Items), n)
	}
}

func runResourceTrackingTest(f *framework.Framework, podsPerNode int, nodeNames sets.String, rm *framework.ResourceMonitor,
	expectedCPU map[string]map[float64]float64, expectedMemory framework.ResourceUsagePerContainer) {
	numNodes := nodeNames.Len()
	totalPods := podsPerNode * numNodes
	By(fmt.Sprintf("Creating a RC of %d pods and wait until all pods of this RC are running", totalPods))
	rcName := fmt.Sprintf("resource%d-%s", totalPods, string(util.NewUUID()))

	// TODO: Use a more realistic workload
	Expect(framework.RunRC(framework.RCConfig{
		Client:    f.Client,
		Name:      rcName,
		Namespace: f.Namespace.Name,
		Image:     "gcr.io/google_containers/pause:2.0",
		Replicas:  totalPods,
	})).NotTo(HaveOccurred())

	// Log once and flush the stats.
	rm.LogLatest()
	rm.Reset()

	By("Start monitoring resource usage")
	// Periodically dump the cpu summary until the deadline is met.
	// Note that without calling framework.ResourceMonitor.Reset(), the stats
	// would occupy increasingly more memory. This should be fine
	// for the current test duration, but we should reclaim the
	// entries if we plan to monitor longer (e.g., 8 hours).
	deadline := time.Now().Add(monitoringTime)
	for time.Now().Before(deadline) {
		timeLeft := deadline.Sub(time.Now())
		framework.Logf("Still running...%v left", timeLeft)
		if timeLeft < reportingPeriod {
			time.Sleep(timeLeft)
		} else {
			time.Sleep(reportingPeriod)
		}
		logPodsOnNodes(f.Client, nodeNames.List())
	}

	By("Reporting overall resource usage")
	logPodsOnNodes(f.Client, nodeNames.List())
	usageSummary, err := rm.GetLatest()
	Expect(err).NotTo(HaveOccurred())
	// TODO(random-liu): Remove the original log when we migrate to new perfdash
	framework.Logf("%s", rm.FormatResourceUsage(usageSummary))
	// Log perf result
	framework.PrintPerfData(framework.ResourceUsageToPerfData(rm.GetMasterNodeLatest(usageSummary)))
	verifyMemoryLimits(f.Client, expectedMemory, usageSummary)

	cpuSummary := rm.GetCPUSummary()
	framework.Logf("%s", rm.FormatCPUSummary(cpuSummary))
	// Log perf result
	framework.PrintPerfData(framework.CPUUsageToPerfData(rm.GetMasterNodeCPUSummary(cpuSummary)))
	verifyCPULimits(expectedCPU, cpuSummary)

	By("Deleting the RC")
	framework.DeleteRC(f.Client, f.Namespace.Name, rcName)
}

func verifyMemoryLimits(c *client.Client, expected framework.ResourceUsagePerContainer, actual framework.ResourceUsagePerNode) {
	if expected == nil {
		return
	}
	var errList []string
	for nodeName, nodeSummary := range actual {
		var nodeErrs []string
		for cName, expectedResult := range expected {
			container, ok := nodeSummary[cName]
			if !ok {
				nodeErrs = append(nodeErrs, fmt.Sprintf("container %q: missing", cName))
				continue
			}

			expectedValue := expectedResult.MemoryRSSInBytes
			actualValue := container.MemoryRSSInBytes
			if expectedValue != 0 && actualValue > expectedValue {
				nodeErrs = append(nodeErrs, fmt.Sprintf("container %q: expected RSS memory (MB) < %d; got %d",
					cName, expectedValue, actualValue))
			}
		}
		if len(nodeErrs) > 0 {
			errList = append(errList, fmt.Sprintf("node %v:\n %s", nodeName, strings.Join(nodeErrs, ", ")))
			heapStats, err := framework.GetKubeletHeapStats(c, nodeName)
			if err != nil {
				framework.Logf("Unable to get heap stats from %q", nodeName)
			} else {
				framework.Logf("Heap stats on %q\n:%v", nodeName, heapStats)
			}
		}
	}
	if len(errList) > 0 {
		framework.Failf("Memory usage exceeding limits:\n %s", strings.Join(errList, "\n"))
	}
}

func verifyCPULimits(expected framework.ContainersCPUSummary, actual framework.NodesCPUSummary) {
	if expected == nil {
		return
	}
	var errList []string
	for nodeName, perNodeSummary := range actual {
		var nodeErrs []string
		for cName, expectedResult := range expected {
			perContainerSummary, ok := perNodeSummary[cName]
			if !ok {
				nodeErrs = append(nodeErrs, fmt.Sprintf("container %q: missing", cName))
				continue
			}
			for p, expectedValue := range expectedResult {
				actualValue, ok := perContainerSummary[p]
				if !ok {
					nodeErrs = append(nodeErrs, fmt.Sprintf("container %q: missing percentile %v", cName, p))
					continue
				}
				if actualValue > expectedValue {
					nodeErrs = append(nodeErrs, fmt.Sprintf("container %q: expected %.0fth%% usage < %.3f; got %.3f",
						cName, p*100, expectedValue, actualValue))
				}
			}
		}
		if len(nodeErrs) > 0 {
			errList = append(errList, fmt.Sprintf("node %v:\n %s", nodeName, strings.Join(nodeErrs, ", ")))
		}
	}
	if len(errList) > 0 {
		framework.Failf("CPU usage exceeding limits:\n %s", strings.Join(errList, "\n"))
	}
}

func inList(c string, list []string) bool {
	for i := range list {
		if list[i] == c {
			return true
		}
	}
	return false
}

// Slow by design (1 hour)
var _ = framework.KubeDescribe("Kubelet [Serial] [Slow]", func() {
	var nodeNames sets.String
	f := framework.NewDefaultFramework("kubelet-perf")
	var rm *framework.ResourceMonitor

	// A list of containers for which we want to collect resource usage.
	var containers []string

	BeforeEach(func() {
		nodes := framework.ListSchedulableNodesOrDie(f.Client)
		nodeNames = sets.NewString()
		for _, node := range nodes.Items {
			nodeNames.Insert(node.Name)
		}
		// Fail if there is no node to tst.
		if len(nodes.Items) == 0 {
			framework.Failf("No nodes to test")
		}
		containers = []string{
			framework.RootContainerName,
			stats.SystemContainerKubelet,
		}
		// Assume all nodes run the same contianer runtime. Only check
		// container runtime stats if the runtime is docker.
		if strings.HasPrefix(nodes.Items[0].Status.NodeInfo.ContainerRuntimeVersion, "docker") {
			containers = append(containers, stats.SystemContainerRuntime)
		}
		rm = framework.NewResourceMonitor(f.Client, containers, containerStatsPollingPeriod)
		if err := rm.Start(); err != nil {
			framework.Failf("Failed to start the resource monitor: %v", err)
		}
	})

	AfterEach(func() {
		rm.Stop()
	})
	framework.KubeDescribe("regular resource usage tracking", func() {
		// We assume that the scheduler will make reasonable scheduling choices
		// and assign ~N pods on the node.
		// Although we want to track N pods per node, there are N + add-on pods
		// in the cluster. The cluster add-on pods can be distributed unevenly
		// among the nodes because they are created during the cluster
		// initialization. This *noise* is obvious when N is small. We
		// deliberately set higher resource usage limits to account for the
		// noise.
		rTests := []resourceTest{
			{
				podsPerNode: 0,
				cpuLimits: framework.ContainersCPUSummary{
					stats.SystemContainerKubelet: {0.50: 0.06, 0.95: 0.08},
					stats.SystemContainerRuntime: {0.50: 0.05, 0.95: 0.06},
				},
				// We set the memory limits generously because the distribution
				// of the addon pods affect the memory usage on each node.
				memLimits: framework.ResourceUsagePerContainer{
					stats.SystemContainerKubelet: &framework.ContainerResourceUsage{MemoryRSSInBytes: 70 * 1024 * 1024},
					stats.SystemContainerRuntime: &framework.ContainerResourceUsage{MemoryRSSInBytes: 85 * 1024 * 1024},
				},
				containers: containers,
			},
			{
				podsPerNode: 35,
				cpuLimits: framework.ContainersCPUSummary{
					stats.SystemContainerKubelet: {0.50: 0.12, 0.95: 0.14},
					stats.SystemContainerRuntime: {0.50: 0.06, 0.95: 0.08},
				},
				// We set the memory limits generously because the distribution
				// of the addon pods affect the memory usage on each node.
				memLimits: framework.ResourceUsagePerContainer{
					stats.SystemContainerRuntime: &framework.ContainerResourceUsage{MemoryRSSInBytes: 100 * 1024 * 1024},
				},
				containers: containers,
			},
			{
				// TODO(yujuhong): Set the limits after collecting enough data.
				podsPerNode: 10,
				containers:  containers,
			},
		}
		for _, testArg := range rTests {
			itArg := testArg
			podsPerNode := itArg.podsPerNode
			name := fmt.Sprintf(
				"resource tracking for %d pods per node", podsPerNode)
			It(name, func() {
				// filter out limits for containers that are not applicable in
				// the current setting.
				for c, _ := range itArg.cpuLimits {
					if !inList(c, itArg.containers) {
						delete(itArg.cpuLimits, c)
					}
				}
				for c, _ := range itArg.memLimits {
					if !inList(c, itArg.containers) {
						delete(itArg.memLimits, c)
					}
				}
				runResourceTrackingTest(f, podsPerNode, nodeNames, rm, itArg.cpuLimits, itArg.memLimits)
			})
		}
	})
	framework.KubeDescribe("experimental resource usage tracking [Feature:ExperimentalResourceUsageTracking]", func() {
		density := []int{100}
		for i := range density {
			podsPerNode := density[i]
			name := fmt.Sprintf(
				"resource tracking for %d pods per node", podsPerNode)
			It(name, func() {
				runResourceTrackingTest(f, podsPerNode, nodeNames, rm, nil, nil)
			})
		}
	})
})
