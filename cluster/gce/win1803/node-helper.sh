#!/usr/bin/env bash

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

# A library of helper functions and constant for windows server 1803
#
# WARNING:
#  The function names in this file should not collide with names in
#  ../gci/helper.sh because they can be sourced by the cluster bring-up
#  scripts at the same time. Add "-windows-" to all function names.

function get-windows-version {
  if [[ "${WINDOWS_NODE_OS_DISTRIBUTION}" == "win1803" ]]; then
  # Only 1803 is supported today.
    echo "1709"
  fi
}

function get-windows-node-instance-metadata-from-file {
  local win_version="$(get-windows-version)"
  local metadata=""
  metadata+="kube-env=${KUBE_TEMP}/windows-node-kube-env.yaml,"
  metadata+="kubelet-config=${KUBE_TEMP}/windows-node-kubelet-config.yaml,"
  metadata+="cluster-location=${KUBE_TEMP}/cluster-location.txt,"
  metadata+="cluster-name=${KUBE_TEMP}/cluster-name.txt,"
  # Note: To get startup script output, run
  #   `gcloud compute instances get-serial-port-output <instance>`
  metadata+="windows-startup-script-ps1=${KUBE_ROOT}/cluster/gce/win${win_version}/configure.ps1,"
  metadata+="${NODE_EXTRA_METADATA}"
  echo "${metadata}"
}

function get-windows-node-instance-metadata {
  local win_version="$(get-windows-version)"
  local metadata=""
  metadata+="serial-port-enable=1,"
  # TODO(yujuhong): Do we need win-version?
  metadata+="win-version=${win_version},"
  # TODO: This is a temporary workaround. We should be passing the url to
  # download the binaries directly.
  metadata+="k8s-version=${KUBE_VERSION:-v1.11.3}"
  echo "${metadata}"
}

# $1: template name (required).
function create-windows-node-instance-template {
  local template_name="$1"
  create-windows-node-template "${template_name}" "${scope_flags[*]}" "$(get-windows-node-instance-metadata-from-file)" "$(get-windows-node-instance-metadata)"
}
