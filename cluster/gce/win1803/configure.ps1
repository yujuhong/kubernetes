# TODO: copyright / license statement.

Import-Module k8s-node-setup.psm1
$ErrorActionPreference = 'Stop'

try {
  Set-EnvironmentVariables
  Set-PrerequisiteOptions
  $kubeEnv = Download-KubeEnv
  Create-PauseImage
  DownloadAndInstall-KubernetesBinaries
  Configure-CniNetworking
  Create-KubeletKubeconfig
  Configure-HostNetworkingService
  Configure-Kubelet
  Start-WorkerServices
  Write-Host 'Waiting 20 seconds for node to join cluster.'
  Start-Sleep 20
  Verify-WorkerServices
}
catch {
  Write-Host 'Exception caught in script:'
  Write-Host $_.InvocationInfo.PositionMessage
  Write-Host "Kubernetes Windows node setup failed: $($_.Exception.Message)"
  exit 1
}
