# TODO: copyright / license statement.

# TODOs to get this thing working:
# - fetch KUBELET_CONFIG (kubelet-config.yaml).
# - fetch KUBECONFIG (the thing that lets kubelet work on the node).

$ErrorActionPreference = 'Stop'
$k8sDir = "C:\etc\kubernetes"

function Set-EnvironmentVariables {
  [Environment]::SetEnvironmentVariable(
    "K8S_DIR", "${k8sDir}", "Machine")
  [Environment]::SetEnvironmentVariable(
    "NODE_DIR", "${k8sDir}\node", "Machine")
  [Environment]::SetEnvironmentVariable(
    "Path", $env:Path + ";${k8sDir}\node", "Machine")
  [Environment]::SetEnvironmentVariable(
    "CNI_DIR", "${k8sDir}\cni", "Machine")
  [Environment]::SetEnvironmentVariable(
    "KUBELET_CONFIG", "${k8sDir}\kubelet-config.yaml", "Machine")
  [Environment]::SetEnvironmentVariable(
    "KUBECONFIG", "${k8sDir}\$(hostname).kubeconfig", "Machine")
  [Environment]::SetEnvironmentVariable(
    "KUBE_NETWORK", "l2bridge", "Machine")
}

function Set-PrerequisiteOptions {
  # Disable Windows firewall.
  Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False
  # Use TLS 1.2: needed for Invoke-WebRequest to github.com.
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}

function Get-MetadataValue {
  param (
    [parameter(Mandatory=$true)]
      [string]$key,
    [parameter(Mandatory=$false)]
      [string]$default
  )

  $url = "http://metadata.google.internal/computeMetadata/v1/instance/attributes/$key"
  try {
    $client = New-Object Net.WebClient
    $client.Headers.Add('Metadata-Flavor', 'Google')
    return ($client.DownloadString($url)).Trim()
  }
  catch [System.Net.WebException] {
    if ($default) {
      return $default
    }
    else {
      Write-Output "Failed to retrieve value for $key."
      return $null
    }
  }
}

function Create-PauseImage {
  #$winVersion = "$([System.Text.Encoding]::ASCII.GetString((`
  #  Invoke-WebRequest -UseBasicParsing -H @{'Metadata-Flavor' = 'Google'} `
  #  http://metadata.google.internal/computeMetadata/v1/instance/attributes/win-version).Content))"
  $winVersion = Get-MetadataValue 'win-version'

  mkdir ${env:K8S_DIR}\pauseimage
  New-Item -ItemType file ${env:K8S_DIR}\pauseimage\Dockerfile
  Set-Content ${env:K8S_DIR}\pauseimage\Dockerfile `
    "FROM microsoft/nanoserver:${winVersion}`n`nCMD cmd /c ping -t localhost"
  docker build -t kubeletwin/pause ${env:K8S_DIR}\pauseimage
}

function DownloadAndInstall-KubernetesBinaries {
  #$k8sVersion = "$(gcloud compute project-info describe `
  #  --format='value(commonInstanceMetadata.items.k8s-version)')"
  $winVersion = Get-MetadataValue 'k8s-version'

  mkdir ${env:NODE_DIR}

  # Disable progress bar to dramatically increase download speed.
  $ProgressPreference = 'SilentlyContinue'
  Invoke-WebRequest `
    https://storage.googleapis.com/kubernetes-release/release/${k8sVersion}/bin/windows/amd64/kubectl.exe `
    -OutFile ${env:NODE_DIR}\kubectl.exe
  Invoke-WebRequest `
    https://storage.googleapis.com/kubernetes-release/release/${k8sVersion}/bin/windows/amd64/kubelet.exe `
    -OutFile ${env:NODE_DIR}\kubelet.exe
  Invoke-WebRequest `
    https://storage.googleapis.com/kubernetes-release/release/${k8sVersion}/bin/windows/amd64/kube-proxy.exe `
    -OutFile ${env:NODE_DIR}\kube-proxy.exe
}

function Configure-CniNetworking {
  mkdir ${env:CNI_DIR}
  Invoke-WebRequest `
    https://github.com/Microsoft/SDN/raw/master/Kubernetes/windows/cni/wincni.exe `
    -OutFile ${env:CNI_DIR}\wincni.exe

  $vethIp = (Get-NetAdapter | Where-Object Name -Like "vEthernet (*" |`
    Get-NetIPAddress -AddressFamily IPv4).IPAddress
  $podCidr = "$([System.Text.Encoding]::ASCII.GetString((`
    Invoke-WebRequest -UseBasicParsing -H @{'Metadata-Flavor' = 'Google'} `
    http://metadata.google.internal/computeMetadata/v1/instance/attributes/pod-cidr).Content))"

  # For Windows nodes the pod gateway IP address is the .1 address in the pod
  # CIDR for the host, but from inside containers it's the .2 address.
  $podGateway = ${podCidr}.substring(0, ${podCidr}.lastIndexOf('.')) + '.1'
  $podEndpointGateway = ${podCidr}.substring(0, ${podCidr}.lastIndexOf('.')) + '.2'

  mkdir ${env:CNI_DIR}\config
  $l2bridgeConf = "${env:CNI_DIR}\config\l2bridge.conf"
  New-Item -ItemType file ${l2bridgeConf}

  Set-Content ${l2bridgeConf} `
    '{
      "cniVersion":  "0.2.0",
      "name":  "l2bridge",
      "type":  "wincni.exe",
      "master":  "Ethernet",
      "capabilities":  {
          "portMappings":  true
      },
      "dns":  {
          "Nameservers":  [
              "10.32.0.10"
          ],
          "Search": [
              "cluster.local"
          ]
      },
      "AdditionalArgs":  [
          {
              "Name":  "EndpointPolicy",
              "Value":  {
                  "Type":  "OutBoundNAT",
                  "ExceptionList":  [
                      "10.200.0.0/16",
                      "10.32.0.0/24",
                      "10.240.0.0/24"
                  ]
              }
          },
          {
              "Name":  "EndpointPolicy",
              "Value":  {
                  "Type":  "ROUTE",
                  "DestinationPrefix":  "10.32.0.0/24",
                  "NeedEncap":  true
              }
          },
          {
              "Name":  "EndpointPolicy",
              "Value":  {
                  "Type":  "ROUTE",
                  "DestinationPrefix":  "VETH_IP/32",
                  "NeedEncap":  true
              }
          }
      ]
  }'.replace('POD_CIDR', ${podCidr}).`
  replace('POD_ENDPOINT_GW', ${podEndpointGateway}).`
  replace('VETH_IP', ${vethIp})
}

try {
  Set-EnvironmentVariables
  Create-PauseImage
  DownloadAndInstall-KubernetesBinaries
}
catch {
  Write-Host 'Exception caught in script:'
  Write-Host $_.InvocationInfo.PositionMessage
  Write-Host "Kubernetes Windows node setup failed: $($_.Exception.Message)"
  exit 1
}
