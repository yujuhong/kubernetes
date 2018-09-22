#!/usr/bin/env bash

# Copyright 2016 The Kubernetes Authors.
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

# A library of helper functions and constant for GCI distro
#echo "PJH: TODO: is cluster/gce/gci/helper.sh needed for Windows?"
source "${KUBE_ROOT}/cluster/gce/gci/helper.sh"

# TODO(pjh): add win-version=1803
function get-node-instance-metadata {
  local win_version=""
  if [[ "${WINDOWS_NODE_OS_DISTRIBUTION}" == "win1709" ]]; then
    win_version="1709"
  else
    win_version="1803"
  fi

  local metadata=""
  metadata+="kube-env=${KUBE_TEMP}/node-kube-env.yaml,"
  metadata+="kubelet-config=${KUBE_TEMP}/node-kubelet-config.yaml,"
  #metadata+="user-data=${KUBE_ROOT}/cluster/gce/gci/node.yaml,"
  metadata+="user-data=${KUBE_ROOT}/cluster/gce/windows/node.yaml,"
  #metadata+="configure-sh=${KUBE_ROOT}/cluster/gce/gci/configure.sh,"
  metadata+="cluster-location=${KUBE_TEMP}/cluster-location.txt,"
  metadata+="cluster-name=${KUBE_TEMP}/cluster-name.txt,"
  # How is KUBE_VERSION not already part of kube-env? Whatever...
  metadata+="k8s-version=${KUBE_VERSION},"
  metadata+="win-version=${win_version},"
  metadata+="${NODE_EXTRA_METADATA}"
  echo "${metadata}"
}

# $1: template name (required).
function create-windows-node-instance-template {
  local template_name="$1"
  echo "PJH: TODO: what is ensure-gci-metadata-files? Fork it or remove it for windows."
  ensure-gci-metadata-files
  create-node-template "${template_name}" "${scope_flags[*]}" "$(get-node-instance-metadata)" "windows"
}
