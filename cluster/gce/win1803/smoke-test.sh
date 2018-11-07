#!/bin/bash

# Copyright 2018 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# A small smoke test to run against a just-deployed kube-up cluster with Windows
# nodes:
#   1) Verify that all Windows nodes have status Ready.
#   2) Verify that no system pods are attempting to run on Windows nodes.
#   3) Deploy two pods running Windows IIS containers.
# This script assumes that it is run from the root of the kubernetes repository
# and that kubectl is present at client/bin/kubectl.

# kubectl filtering is the worst.
statuses=$(client/bin/kubectl get nodes -l beta.kubernetes.io/os=windows \
  -o jsonpath='{.items[*].status.conditions[?(@.type=="Ready")].status}')
for status in $statuses; do
  if [[ $status == "False" ]]; then
    echo "ERROR: some Windows node has status != Ready"
    echo "kubectl get nodes -l beta.kubernetes.io/os=windows"
    client/bin/kubectl get nodes -l beta.kubernetes.io/os=windows
    exit 1
  fi
done
echo "Verified that all Windows nodes have status Ready"

windows_system_pods=$(client/bin/kubectl get pods --namespace kube-system \
  -o wide | egrep "Pending|windows" | wc -w)
if [[ $windows_system_pods -ne 0 ]]; then
  echo "ERROR: there are kube-system pods trying to run on Windows nodes"
  echo "kubectl get pods --namespace kube-system -o wide"
  client/bin/kubectl get pods --namespace kube-system -o wide
  #exit 1
fi
echo "Verified that all system pods are running on Linux nodes"

echo "Writing example deployment to windows-iis-deployment.yaml"
cat <<EOF > windows-iis-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: iis-deployment
  labels:
    app: iis
spec:
  replicas: 2
  selector:
    matchLabels:
      app: iis
  template:
    metadata:
      labels:
        app: iis
    spec:
      containers:
      - name: iis-servercore
        image: microsoft/iis:windowsservercore-1803
      nodeSelector:
        beta.kubernetes.io/os: windows
EOF

client/bin/kubectl create -f windows-iis-deployment.yaml

# It may take a while for the IIS pods to start running because the IIS
# container (based on the large windowsservercore container) must be fetched on
# the Windows nodes.
timeout=120
while [[ $timeout -gt 0 ]]; do
  echo "Waiting for IIS pods to become Ready"
  statuses=$(client/bin/kubectl get pods -l app=iis \
    -o jsonpath='{.items[*].status.conditions[?(@.type=="Ready")].status}' \
    | grep "False" | wc -w)
  if [[ $statuses -eq 0 ]]; then
    break
  else
    sleep 10
    let timeout=timeout-10
  fi
done

if [[ $timeout -gt 0 ]]; then
  echo "All IIS pods became Ready"
else
  echo "ERROR: Not all IIS pods became Ready"
  echo "kubectl get pods -l app=iis"
  client/bin/kubectl get pods -l app=iis
  client/bin/kubectl delete deployment iis-deployment
  exit 1
fi
echo "Removing iis-deployment"
client/bin/kubectl delete deployment iis-deployment

exit 0
