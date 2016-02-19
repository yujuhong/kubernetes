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
	"time"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/util"
	"k8s.io/kubernetes/pkg/util/sets"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func runStressTest(framework *Framework, podsPerNode int, nodeNames sets.String) {
	numNodes := nodeNames.Len()
	totalPods := podsPerNode * numNodes
	By(fmt.Sprintf("Creating a RC of %d pods and wait until all pods of this RC are running", totalPods))
	rcName := fmt.Sprintf("resource%d-%s", totalPods, string(util.NewUUID()))

	start := time.Now()
	Expect(RunRC(RCConfig{
		Client:    framework.Client,
		Name:      rcName,
		Namespace: framework.Namespace.Name,
		Image:     "gcr.io/google_containers/pause:2.0",
		Replicas:  totalPods,
	})).NotTo(HaveOccurred())
	Logf("Startup time for %d pods: %v", totalPods, time.Since(start))

	By("Deleting the RC")
	DeleteRCWithOptions(framework.Client, framework.Namespace.Name, rcName, 2*time.Minute, &api.DeleteOptions{})
}

var _ = Describe("Kubelet [Serial] [Slow]", func() {
	var nodeNames sets.String
	framework := NewFramework("kubelet-stress")

	BeforeEach(func() {
		// It should be OK to list unschedulable Nodes here.
		nodes, err := framework.Client.Nodes().List(api.ListOptions{})
		expectNoError(err)
		nodeNames = sets.NewString()
		for _, node := range nodes.Items {
			nodeNames.Insert(node.Name)
		}
	})

	Describe("stress testing", func() {
		density := []int{100}
		for i := range density {
			podsPerNode := density[i]
			name := fmt.Sprintf(
				"for %d pods per node", podsPerNode)
			It(name, func() {
				// Run N times until it fails.
				for i := 0; i < 10; i++ {
					By(fmt.Sprintf("Running test %d", i))
					runStressTest(framework, podsPerNode, nodeNames)
				}
			})
		}
	})
})
