# Starting a Windows Kubernetes cluster on GCE using kube-up

## Building the cluster

Prerequisites: a Google Cloud Platform project.

On a Linux machine: clone this repository under your `$GOPATH/src` directory
then run:

```
# Checkout the Windows branch:
git checkout windows-up

# Remove files that interfere with get-kube / kube-up:
rm -rf ./kubernetes/; rm -f kubernetes.tar.gz; rm -f ~/.kube/config

# Set environment variables needed by kube-up scripts:
source cluster/gce/kube-up-gce-windows-netd.env

# Build the kubernetes binaries locally. This eliminates the need to run
# get-kube.
# TODO(pjh): figure out how to get docker-based build working. Does kube-up
# really need all of the release binaries built, or just kubectl?
make bazel-build && make bazel-release

# Invoke kube-up.sh with these environment variables:
#   PROJECT: text name of your GCP project.
#   KUBERNETES_SKIP_CONFIRM: skips any kube-up prompts.
PROJECT=<your_project_name> KUBERNETES_SKIP_CONFIRM=y ./cluster/kube-up.sh
```

The result should be a Kubernetes cluster with one Linux master node, two Linux
worker nodes and two Windows worker nodes. The Linux nodes will use the `netd`
CNI plugin and the Windows nodes will use `wincni`.

To teardown the cluster run:

```
PROJECT=<your_project_name> KUBERNETES_SKIP_CONFIRM=y ./cluster/kube-down.sh
```

TODO(pjh): add NUM_LINUX_NODES and NUM_WINDOWS_NODES to
kube-up-gce-windows-netd.env.

## Running tests against the cluster

These steps are based on the
[e2e-win-prow-deployment](https://github.com/e2e-win/e2e-win-prow-deployment)
steps.

*   Ensure that you're using the patched `cluster/local/util.sh` in this branch.

*   If necessary run `alias kubectl=client/bin/kubectl` .

*   Set the following environment variables (these values should make sense if
    you built your cluster using the kube-up steps above):

    ```
    export KUBE_HOME=$(pwd)
    export KUBECONFIG=~/.kube/config
    export KUBE_MASTER=local
    export KUBE_MASTER_NAME=kubernetes-master
    export KUBE_MASTER_IP=$(kubectl get node ${KUBE_MASTER_NAME} -o jsonpath='{.status.addresses[?(@.type=="ExternalIP")].address}')
    export KUBE_MASTER_URL=https://${KUBE_MASTER_IP}
    export KUBE_MASTER_PORT=443
    ```

*   Download the list of Windows e2e tests:

    ```
    curl https://raw.githubusercontent.com/e2e-win/e2e-win-prow-deployment/master/repo-list.txt -o ${KUBE_HOME}/repo-list.yaml
    export KUBE_TEST_REPO_LIST=${KUBE_HOME}/repo-list.yaml
    ```

*   Verify that all system pods are running successfully on Linux nodes:

    ```
    kubectl get pods --all-namespaces -o wide
    ```

*   Taint the Linux nodes so that test pods will not land on them:

    ```
    export LINUX_NODES=$(kubectl get nodes -l beta.kubernetes.io/os=linux,kubernetes.io/hostname!=${KUBE_MASTER_NAME} -o name)
    export LINUX_NODE_COUNT=$(echo ${LINUX_NODES} | wc -w)
    for node in $LINUX_NODES; do
      kubectl taint node $node node-under-test=false:NoSchedule
    done
    ```

*   Build necessary test binaries:

    ```
    make WHAT=test/e2e/e2e.test
    ```

*   Run the tests with flags that point at the "local" (already-running) cluster
    and that permit the `NoSchedule` Linux nodes:

    ```
    go run ${KUBE_HOME}/hack/e2e.go -- --verbose-commands --check-version-skew=false --test --provider=local --test_args=--"ginkgo.focus=\[Conformance\] --allowed-not-ready-nodes=${LINUX_NODE_COUNT} --report-dir=${KUBE_HOME}/e2e-reports" &> ${KUBE_HOME}/conformance.out
    ```

    TODO: skip known, incompatible tests so that the test suite can finish in a
    reasonable time.
