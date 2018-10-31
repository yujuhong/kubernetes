# TODO: copyright / license statement.

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
