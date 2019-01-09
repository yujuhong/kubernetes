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

<#
.SYNOPSIS
  Top-level script that runs on Windows nodes to join them to the K8s cluster.
#>

$ErrorActionPreference = 'Stop'

# Update TLS setting to enable Github downloads and disable progress bar to
# increase download speed.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ProgressPreference = 'SilentlyContinue'

function Get-MetadataValue {
  param (
    [parameter(Mandatory=$true)] [string]$Key,
    [parameter(Mandatory=$false)] [string]$Default
  )

  $url = ("http://metadata.google.internal/computeMetadata/v1/instance/" +
          "attributes/$Key")
  try {
    $client = New-Object Net.WebClient
    $client.Headers.Add('Metadata-Flavor', 'Google')
    return ($client.DownloadString($url)).Trim()
  }
  catch [System.Net.WebException] {
    if ($Default) {
      return $Default
    }
    else {
      Write-Output "Failed to retrieve value for $Key."
      return $null
    }
  }
}

try {
  $node_setup_module = Get-MetadataValue 'k8s-node-setup-psm1'
  New-Item -ItemType file C:\k8s-node-setup.psm1
  Set-Content C:\k8s-node-setup.psm1 $node_setup_module
  Import-Module C:\k8s-node-setup.psm1

  $install_ssh_module = Get-MetadataValue 'install-ssh-psm1'
  New-Item -ItemType file C:\install-ssh.psm1
  Set-Content C:\install-ssh.psm1 $install_ssh_module
  Import-Module C:\install-ssh.psm1

  InstallAndStart-OpenSSH
  Log-Output "Installed OpenSSH, sshd is running"

  StartProcess-WriteSshKeys
  Log-Output "Started background process to write SSH keys"

  Set-EnvironmentVars
  Set-PrerequisiteOptions
  Create-Directories
  Download-HelperScripts

  $kube_env = Download-KubeEnv
  Create-PauseImage
  DownloadAndInstall-KubernetesBinaries
  Create-NodePki
  Create-KubeletKubeconfig
  Create-KubeproxyKubeconfig
  Set-PodCidr
  Add-InitialHnsNetwork
  Configure-HostNetworkingService
  Configure-CniNetworking
  Configure-Kubelet

  Start-WorkerServices
  Write-Host 'Waiting 15 seconds for node to join cluster.'
  Start-Sleep 15
  Verify-WorkerServices

  $prepull_images_module = Get-MetadataValue 'prepull-images-psm1'
  New-Item -ItemType file C:\prepull-images.psm1
  Set-Content C:\prepull-images.psm1 $prepull_images_module
  Import-Module C:\prepull-images.psm1

  Prepull-E2EImages
}
catch {
  Write-Host 'Exception caught in script:'
  Write-Host $_.InvocationInfo.PositionMessage
  Write-Host "Kubernetes Windows node setup failed: $($_.Exception.Message)"
  exit 1
}
