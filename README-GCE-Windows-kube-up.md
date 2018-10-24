# Starting a Windows Kubernetes cluster on GCE using kube-up

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

TODO(pjh): add NUM_LINUX_NODES and NUM_WINDOWS_NODES to
kube-up-gce-windows-netd.env.
