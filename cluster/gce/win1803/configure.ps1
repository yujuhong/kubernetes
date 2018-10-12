# TODO: copyright / license statement.

# TODOs to get this thing working:
# - set pod-cidr metadata key correctly. Really, need to fetch kube-env metadata
#   value (node-kube-env.yaml) and capture CLUSTER_IP_RANGE,
#   SERVICE_CLUSTER_IP_RANGE, KUBERNETES_MASTER_NAME, DNS_SERVER_IP,
#   DNS_DOMAIN, etc. If you're not sure what to do, review what Linux startup
#   script does and imitate it!
# - fetch KUBELET_CONFIG (kubelet-config.yaml).
# - fetch KUBECONFIG (the thing that lets kubelet work on the node).
# - If this startup script is too large (I suspect it will be), use a small
#   startup script that downloads it from Github and invokes it.

$ErrorActionPreference = 'Stop'
$k8sDir = "C:\etc\kubernetes"

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

# Fetches the kube-env from the instance metadata.
# Returns: a PowerShell Hashtable object containing the key-value pairs from
#   kube-env.
function Download-KubeEnv {
  $kubeEnv = Get-MetadataValue 'kube-env'
  $kubeEnvTable = @{}
  ForEach ($line in $($kubeEnv.Split("`r`n"))) {
    # TODO(pjh): the kube-env has some values that contain newlines (e.g.
    # CUSTOM_NETD_YAML), which are marked with a '|' character at the beginning
    # of their value. These are not handled correctly at the moment, fix this.
    $key, $value = $line.Split(":")
    if($key -eq "") {
      # Splitting kube-env on newlines fails for values that contain newlines;
      # in these cases we'll end up with an empty key, just skip them.
      continue
    }
    try {
      $value = $value.Split("'")[1]
    }
    catch [System.Management.Automation.RuntimeException] {
      # Weird values (e.g. those that begin with '|', see note above) will end
      # up here.
      $value = ""
    }
    $kubeEnvTable.Add(${key}, ${value})
  }
  #$kubeEnvTable | Format-Table
  return $kubeEnvTable
}

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
  # TODO(pjh): disable automatic Windows Updates + restarts?
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
  # TODO(pjh): switch to using win-bridge plugin instead of wincni.
  # https://github.com/containernetworking/plugins/tree/master/plugins/main/windows/win-bridge
  mkdir ${env:CNI_DIR}
  Invoke-WebRequest `
    https://github.com/Microsoft/SDN/raw/master/Kubernetes/windows/cni/wincni.exe `
    -OutFile ${env:CNI_DIR}\wincni.exe

  #$vethIp = (Get-NetAdapter | Where-Object Name -Like "vEthernet (*" |`
  $vethIp = (Get-NetAdapter | Where-Object Name -Like "vEthernet (nat*" |`
    Get-NetIPAddress -AddressFamily IPv4).IPAddress

  mkdir ${env:CNI_DIR}\config
  $l2bridgeConf = "${env:CNI_DIR}\config\l2bridge.conf"
  New-Item -ItemType file ${l2bridgeConf}

  # TODO(pjh): need to fill in appropriate cluster CIDR values here! See
  # https://github.com/Microsoft/SDN/blob/master/Kubernetes/windows/start-kubelet.ps1#L133
  # for what values go where.
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
  }'.replace('VETH_IP', ${vethIp})
}

function Configure-HostNetworkingService {
  $endpointName = "cbr0"
  $vnicName = "vEthernet ($endpointName)"

  Invoke-WebRequest `
    https://github.com/Microsoft/SDN/raw/master/Kubernetes/windows/hns.psm1 `
    -OutFile ${env:K8S_DIR}\hns.psm1
  Import-Module ${env:K8S_DIR}\hns.psm1

  # BOOKMARK XXX TODO: run the kubelet once here to get the podCidr!
  # https://github.com/Microsoft/SDN/blob/master/Kubernetes/windows/start-kubelet.ps1#L180
  #
  # Then:
  # $podCIDR=c:\k\kubectl.exe --kubeconfig=c:\k\config get nodes/$($(hostname).ToLower()) -o custom-columns=podCidr:.spec.podCIDR --no-headers

  #### TODO(pjh): pod-cidr is 10.200.${i}.0/24 for k8s-hard-way; goes into the
  #### KUBELET_CONFIG that's passed to kubelet via --config flag.
  ###$podCidr = Get-MetadataValue 'pod-cidr'

  # For Windows nodes the pod gateway IP address is the .1 address in the pod
  # CIDR for the host, but from inside containers it's the .2 address.
  $podGateway = ${podCidr}.substring(0, ${podCidr}.lastIndexOf('.')) + '.1'
  $podEndpointGateway = `
    ${podCidr}.substring(0, ${podCidr}.lastIndexOf('.')) + '.2'

  New-HNSNetwork -Type "L2Bridge" -AddressPrefix $podCidr -Gateway $podGateway `
    -Name ${env:KUBE_NETWORK} -Verbose
  $hnsNetwork = Get-HnsNetwork | ? Type -EQ "L2Bridge"
  $hnsEndpoint = New-HnsEndpoint -NetworkId $hnsNetwork.Id -Name $endpointName `
    -IPAddress $podEndpointGateway -Gateway "0.0.0.0" -Verbose
  Attach-HnsHostEndpoint -EndpointID $hnsEndpoint.Id -CompartmentID 1 -Verbose
  netsh interface ipv4 set interface "$vnicName" forwarding=enabled
  Get-HNSPolicyList | Remove-HnsPolicyList
}

function Configure-Kubelet {
  Set-Content ${env:KUBELET_CONFIG} `
  'kind: KubeletConfiguration
  apiVersion: kubelet.config.k8s.io/v1beta1
  authentication:
    anonymous:
      enabled: true
    webhook:
      enabled: true
    x509:
      clientCAFile: "K8S_DIR\ca.pem"
  authorization:
    mode: AlwaysAllow
  clusterDomain: "cluster.local"
  clusterDNS:
    - "10.32.0.10"
  podCIDR: "POD_CIDR"
  runtimeRequestTimeout: "15m"
  tlsCertFile: "K8S_DIR\HOSTNAME.pem"
  tlsPrivateKeyFile: "K8S_DIR\HOSTNAME-key.pem"'`
  .replace('K8S_DIR', ${env:K8S_DIR}).`
  replace('POD_CIDR', ${podCidr}).`
  replace('HOSTNAME', `$(hostname)).replace('\', '\\')
}

function Start-WorkerServices {
  # TODO: run these as background jobs, probably. See Yu-Ju's
  # https://paste.googleplex.com/6221572868145152.
  & ${env:NODE_DIR}\kubelet.exe --hostname-override=$(hostname) --v=6 `
    --pod-infra-container-image=kubeletwin/pause --resolv-conf="" `
    --allow-privileged=true --config=${env:KUBELET_CONFIG} `
    --enable-debugging-handlers `
    --kubeconfig=${env:K8S_DIR}\$(hostname).kubeconfig `
    --hairpin-mode=promiscuous-bridge `
    --image-pull-progress-deadline=20m --cgroups-per-qos=false `
    --enforce-node-allocatable="" --network-plugin=cni `
    --cni-bin-dir="${env:CNI_DIR}" `
    --cni-conf-dir="${env:CNI_DIR}\config" --register-node=true

  Start-Sleep 10

  & ${env:NODE_DIR}\kube-proxy.exe --v=4 --proxy-mode=kernelspace `
    --hostname-override=$(hostname) `
    --kubeconfig=${env:K8S_DIR}\kube-proxy.kubeconfig `
    --cluster-cidr="10.200.0.0/16"
}

function Verify-WorkerServices {
  & ${env:K8S_DIR}\node\kubectl get nodes
}

try {
  Set-EnvironmentVariables
  Set-PrerequisiteOptions
  $kubeEnv = Download-KubeEnv
  Create-PauseImage
  DownloadAndInstall-KubernetesBinaries
  Configure-CniNetworking
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
