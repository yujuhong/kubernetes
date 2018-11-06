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

$ErrorActionPreference = 'Stop'

# Update TLS setting to enable Github downloads and disable progress bar to
# increase download speed.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ProgressPreference = 'SilentlyContinue'

try {
  Invoke-WebRequest `
    https://github.com/pjh/kubernetes/raw/windows-up/cluster/gce/win1803/install-ssh.psm1 `
    -OutFile C:\install-ssh.psm1
  Import-Module C:\install-ssh.psm1

  Invoke-WebRequest `
    https://github.com/pjh/kubernetes/raw/windows-up/cluster/gce/win1803/k8s-node-setup.psm1 `
    -OutFile C:\k8s-node-setup.psm1
  Import-Module C:\k8s-node-setup.psm1

  InstallAndStart-OpenSSH
  Log "Installed OpenSSH, sshd is running"

  Set-EnvironmentVars
  Set-PrerequisiteOptions
  Create-Directories

  $kubeEnv = Download-KubeEnv
  Create-PauseImage
  DownloadAndInstall-KubernetesBinaries
  Configure-CniNetworking
  Create-NodePki
  Create-KubeletKubeconfig
  Create-KubeproxyKubeconfig
  RunKubeletOnceToGet-PodCidr
  Write-Host 'Stopping before Configure-HostNetworkingService'
  Configure-HostNetworkingService
  Configure-Kubelet

  Start-WorkerServices
  Write-Host 'Waiting 15 seconds for node to join cluster.'
  Start-Sleep 15
  Verify-WorkerServices
}
catch {
  Write-Host 'Exception caught in script:'
  Write-Host $_.InvocationInfo.PositionMessage
  Write-Host "Kubernetes Windows node setup failed: $($_.Exception.Message)"
  exit 1
}
