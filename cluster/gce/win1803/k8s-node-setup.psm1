# TODO: copyright / license statement.

# Suggested usage for dev/test:
#   [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
#   Invoke-WebRequest https://github.com/pjh/kubernetes/raw/windows-up/cluster/gce/win1803/k8s-node-setup.psm1 -OutFile k8s-node-setup.psm1
#   Invoke-WebRequest https://github.com/pjh/kubernetes/raw/windows-up/cluster/gce/win1803/configure.ps1 -OutFile configure.ps1
#   Import-Module -Force .\k8s-node-setup.psm1  # -Force to override existing
#   # Execute functions manually or run configure.ps1.
#
# TODOs to get this thing working:
# - set pod-cidr metadata key correctly. Really, need to fetch kube-env metadata
#   value (node-kube-env.yaml) and capture CLUSTER_IP_RANGE,
#   SERVICE_CLUSTER_IP_RANGE, KUBERNETES_MASTER_NAME, DNS_SERVER_IP,
#   DNS_DOMAIN, etc. If you're not sure what to do, review what Linux startup
#   script does and imitate it!
# - fetch KUBELET_CONFIG (kubelet-config.yaml).
# - If this startup script is too large (I suspect it will be), use a small
#   startup script that downloads it from Github and invokes it.

$k8sDir = "C:\etc\kubernetes"
Export-ModuleMember -Variable k8sDir

function Log {
  param (
    [parameter(Mandatory=$true)] [string]$message
  )
  Write-Output "${message}"
}

function Todo {
  param (
    [parameter(Mandatory=$true)] [string]$message
  )
  Write-Output "TODO: ${message}"
}

function NotImplemented {
  param (
    [parameter(Mandatory=$true)] [string]$message,
    [parameter(Mandatory=$false)] [bool]$fail = $false
  )
  Write-Output "Not implemented yet: ${message}"
  If (${fail}) {
    Exit 1
  }
}

function Get-MetadataValue {
  param (
    [parameter(Mandatory=$true)] [string]$key,
    [parameter(Mandatory=$false)] [string]$default
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
  # Testing / debugging:
  # First:
  #   ${kubeEnv} = Get-MetadataValue 'kube-env'
  # or:
  #   ${kubeEnv} = [IO.File]::ReadAllText(".\kubeEnv.txt")
  # ${kubeEnvTable} = ConvertFrom-Yaml ${kubeEnv}
  # ${kubeEnvTable}
  # ${kubeEnvTable}.GetType()

  # The type of kubeEnv is a powershell String.
  ${kubeEnv} = Get-MetadataValue 'kube-env'
  ${kubeEnvTable} = ConvertFrom-Yaml ${kubeEnv}

  return ${kubeEnvTable}
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
    "BOOTSTRAP_KUBECONFIG", "${k8sDir}\$(hostname).bootstrap-kubeconfig",
    "Machine")
  [Environment]::SetEnvironmentVariable(
    "KUBE_NETWORK", "l2bridge", "Machine")
  [Environment]::SetEnvironmentVariable(
    "PKI_DIR", "${k8sDir}\pki", "Machine")
  [Environment]::SetEnvironmentVariable(
    "CA_CERT_BUNDLE_PATH", "${k8sDir}\pki\ca-certificates.crt", "Machine")
  [Environment]::SetEnvironmentVariable(
    "KUBELET_CERT_PATH", "${k8sDir}\pki\kubelet.crt", "Machine")
  [Environment]::SetEnvironmentVariable(
    "KUBELET_KEY_PATH", "${k8sDir}\pki\kubelet.key", "Machine")
  # TODO: copy-paste these for manual testing...
  $env:K8S_DIR = "${k8sDir}"
  $env:NODE_DIR = "${k8sDir}\node"
  $env:Path = $env:Path + ";${k8sDir}\node"
  $env:CNI_DIR = "${k8sDir}\cni"
  $env:KUBELET_CONFIG = "${k8sDir}\kubelet-config.yaml"
  $env:KUBECONFIG = "${k8sDir}\$(hostname).kubeconfig"
  $env:BOOTSTRAP_KUBECONFIG = "${k8sDir}\$(hostname).bootstrap-kubeconfig"
  $env:KUBE_NETWORK = "l2bridge"
  $env:PKI_DIR = "${k8sDir}\pki"
  $env:CA_CERT_BUNDLE_PATH = "${k8sDir}\pki\ca-certificates.crt"
  $env:KUBELET_CERT_PATH="${k8sDir}\pki\kubelet.crt"
  $env:KUBELET_KEY_PATH="${k8sDir}\pki\kubelet.key"
}

function Set-PrerequisiteOptions {
  # Disable Windows firewall.
  Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False
  # Use TLS 1.2: needed for Invoke-WebRequest to github.com.
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  Todo("disable automatic Windows Updates and restarts")

  # https://github.com/cloudbase/powershell-yaml
  Log("installing powershell-yaml module from external repo")
  Install-Module -Name powershell-yaml -Force
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
  # TODO: kubeletwin/pause should be a variable across these functions.
  docker build -t kubeletwin/pause ${env:K8S_DIR}\pauseimage
}

function DownloadAndInstall-KubernetesBinaries {
  $k8sVersion = Get-MetadataValue 'k8s-version'

  mkdir -Force ${env:NODE_DIR}

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
  Todo("switch to using win-bridge plugin instead of wincni")
  # https://github.com/containernetworking/plugins/tree/master/plugins/main/windows/win-bridge
  mkdir -Force ${env:CNI_DIR}
  Invoke-WebRequest `
    https://github.com/Microsoft/SDN/raw/master/Kubernetes/windows/cni/wincni.exe `
    -OutFile ${env:CNI_DIR}\wincni.exe

  #$vethIp = (Get-NetAdapter | Where-Object Name -Like "vEthernet (*" |`
  $vethIp = (Get-NetAdapter | Where-Object Name -Like "vEthernet (nat*" |`
    Get-NetIPAddress -AddressFamily IPv4).IPAddress

  mkdir -Force ${env:CNI_DIR}\config
  $l2bridgeConf = "${env:CNI_DIR}\config\l2bridge.conf"
  # TODO(pjh): add -Force to overwrite if exists? Or do we want to fail?
  New-Item -ItemType file ${l2bridgeConf}

  Todo("still need to fill in appropriate cluster CIDR values in l2bridge.conf")
  # TODO: see
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

# Decodes the base64 $data string and writes it as binary to $file.
function Write-PkiData() {
  param (
    [parameter(Mandatory=$true)] [string] $data,
    [parameter(Mandatory=$true)] [string] $file
  )

  # This command writes out a PEM certificate file, analogous to "base64
  # --decode" on Linux. See https://stackoverflow.com/a/51914136/1230197.
  [IO.File]::WriteAllBytes($file, [Convert]::FromBase64String($data))
  Todo("need to set permissions correctly on ${file}; not sure what the Windows equivalent of 'umask 077' is")
  # Linux: owned by root, rw by user only.
  #   -rw------- 1 root root 1.2K Oct 12 00:56 ca-certificates.crt
  #   -rw------- 1 root root 1.3K Oct 12 00:56 kubelet.crt
  #   -rw------- 1 root root 1.7K Oct 12 00:56 kubelet.key
  # Windows:
  #   https://docs.microsoft.com/en-us/dotnet/api/system.io.fileattributes
  #   https://docs.microsoft.com/en-us/dotnet/api/system.io.fileattributes
}

# This function is analogous to create-node-pki() in gci/configure-helper.sh for
# Linux nodes.
# Required ${kubeEnv} keys:
#   CA_CERT
#   KUBELET_CERT
#   KUBELET_KEY
function Create-NodePki() {
  echo "Creating node pki files"

  mkdir -Force ${env:PKI_DIR}

  # Note: create-node-pki() tests if CA_CERT_BUNDLE / KUBELET_CERT /
  # KUBELET_KEY are already set, we don't.
  $CA_CERT_BUNDLE = ${kubeEnv}['CA_CERT']
  $KUBELET_CERT = ${kubeEnv}['KUBELET_CERT']
  $KUBELET_KEY = ${kubeEnv}['KUBELET_KEY']

  # Wrap data arg in quotes in case it contains spaces? (does this even make
  # sense?)
  Write-PkiData "${CA_CERT_BUNDLE}" ${env:CA_CERT_BUNDLE_PATH}
  Write-PkiData "${KUBELET_CERT}" ${env:KUBELET_CERT_PATH}
  Write-PkiData "${KUBELET_KEY}" ${env:KUBELET_KEY_PATH}
  Get-ChildItem ${env:PKI_DIR}
}

# This is analogous to create-kubelet-kubeconfig() in gci/configure-helper.sh
# for Linux nodes.
# Create-NodePki() must be called first.
# Required ${kubeEnv} keys:
#   KUBERNETES_MASTER_NAME: the apiserver IP address.
function Create-KubeletKubeconfig() {
  # The API server IP address comes from KUBERNETES_MASTER_NAME in kube-env, I
  # think.
  # http://cs/github/kubernetes/kubernetes/cluster/gce/gci/configure-helper.sh?l=2801&rcl=e4200cea9ced996c54096dc45d65e4dadb43a7ae
  $apiserverAddress = ${kubeEnv}['KUBERNETES_MASTER_NAME']

  # TODO(pjh): set these using kube-env values.
  $createBootstrapConfig = $true
  $fetchBootstrapConfig = $false

  if (${createBootstrapConfig}) {
    New-Item -ItemType file ${env:BOOTSTRAP_KUBECONFIG}
    # TODO(pjh): is user "kubelet" correct? In my guide it's
    #   "system:node:$(hostname)"
    # The kubelet user config uses client-certificate and client-key here; in
    # my guide it's client-certificate-data and client-key-data. Does it matter?
    Set-Content ${env:BOOTSTRAP_KUBECONFIG} `
'apiVersion: v1
kind: Config
users:
- name: kubelet
  user:
    client-certificate: KUBELET_CERT_PATH
    client-key: KUBELET_KEY_PATH
clusters:
- name: local
  cluster:
    server: https://APISERVER_ADDRESS
    certificate-authority: CA_CERT_BUNDLE_PATH
contexts:
- context:
    cluster: local
    user: kubelet
  name: service-account-context
current-context: service-account-context'.`
      replace('KUBELET_CERT_PATH', ${env:KUBELET_CERT_PATH}).`
      replace('KUBELET_KEY_PATH', ${env:KUBELET_KEY_PATH}).`
      replace('APISERVER_ADDRESS', ${apiserverAddress}).`
      replace('CA_CERT_BUNDLE_PATH', ${env:CA_CERT_BUNDLE_PATH})
    Get-Content ${env:BOOTSTRAP_KUBECONFIG}
  } ElseIf (${fetchBootstrapConfig}) {
    NotImplemented("fetching kubelet bootstrap-kubeconfig file from metadata",
      $true)
    # get-metadata-value "instance/attributes/bootstrap-kubeconfig" >/var/lib/kubelet/bootstrap-kubeconfig
    Get-Content ${env:BOOTSTRAP_KUBECONFIG}
  } Else {
    NotImplemented("fetching kubelet kubeconfig file from metadata", $true)
    # get-metadata-value "instance/attributes/kubeconfig" >/var/lib/kubelet/kubeconfig
    Get-Content ${env:KUBECONFIG}
  }
}

function Configure-HostNetworkingService {
  $endpointName = "cbr0"
  $vnicName = "vEthernet ($endpointName)"

  Invoke-WebRequest `
    https://github.com/Microsoft/SDN/raw/master/Kubernetes/windows/hns.psm1 `
    -OutFile ${env:K8S_DIR}\hns.psm1
  Import-Module ${env:K8S_DIR}\hns.psm1

  # BOOKMARK XXX TODO: run the kubelet once here to get the podCidr!
  #   Need to update node bringup so that KUBECONFIG is attached as metadata.
  #   kubelet on Linux node uses:
  #     --bootstrap-kubeconfig=/var/lib/kubelet/bootstrap-kubeconfig
  #     --kubeconfig=/var/lib/kubelet/kubeconfig
  #   How do those files get there? cluster/gce/gci/configure-helper.sh calls
  #   create-kubelet-kubeconfig() which does one of 1) creates a "bootstrap
  #   kubeconfig", 2) fetches the bootstrap kubeconfig from metadata, or 3)
  #   fetches a normal non-bootstrap kubeconfig from metadata. In the case of
  #   1) or 2), the kubelet writes out the non-bootstrap kubeconfig to the path
  #   specified by --kubeconfig on first execution:
  #   https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet-tls-bootstrapping/.
  #     Is a token (KUBE_PROXY_TOKEN?) necessary?
  #
  # Then:
  # $podCIDR=c:\k\kubectl.exe --kubeconfig=c:\k\config get nodes/$($(hostname).ToLower()) -o custom-columns=podCidr:.spec.podCIDR --no-headers
  #   TODO: also need to include args from KUBELET_ARGS in kube-env??
  #     --v=2 --allow-privileged=true --cloud-provider=gce
  #     --experimental-mounter-path=/home/kubernetes/containerized_mounter/mounter
  #     --experimental-check-node-capabilities-before-mount=true
  #     --cert-dir=/var/lib/kubelet/pki/
  #     --dynamic-config-dir=/var/lib/kubelet/dynamic-config
  #     --bootstrap-kubeconfig=/var/lib/kubelet/bootstrap-kubeconfig
  #     --kubeconfig=/var/lib/kubelet/kubeconfig
  #     --cni-bin-dir=/home/kubernetes/bin --network-plugin=cni
  #     --non-masquerade-cidr=0.0.0.0/0
  #     --volume-plugin-dir=/home/kubernetes/flexvolume
  #     --node-labels=beta.kubernetes.io/fluentd-ds-ready=true,cloud.google.com/gke-netd-ready=true
  #     --container-runtime=docker
  $argList = @(`
    #"--hostname-override=$(hostname)",`
    "--pod-infra-container-image=kubeletwin/pause",`
    "--resolv-conf=""""",`
    "--kubeconfig=${env:K8S_DIR}\$(hostname).kubeconfig")

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
  replace('HOSTNAME', $(hostname)).`
  replace('\', '\\')
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

Export-ModuleMember -Function Get-MetadataValue
Export-ModuleMember -Function Download-KubeEnv
Export-ModuleMember -Function Set-EnvironmentVariables
Export-ModuleMember -Function Set-PrerequisiteOptions
Export-ModuleMember -Function Create-PauseImage
Export-ModuleMember -Function DownloadAndInstall-KubernetesBinaries
Export-ModuleMember -Function Configure-CniNetworking
Export-ModuleMember -Function Create-NodePki
Export-ModuleMember -Function Create-KubeletKubeconfig
Export-ModuleMember -Function Configure-HostNetworkingService
Export-ModuleMember -Function Configure-Kubelet
Export-ModuleMember -Function Start-WorkerServices
Export-ModuleMember -Function Verify-WorkerServices

# TODO(pjh): other functions from configure-helper.sh that we may need to
# replicate here:
#function setup-os-params {
#function secure_random {
#function config-ip-firewall {
#function create-dirs {
#function get-local-disk-num() {
#function safe-block-symlink(){
#function get-or-generate-uuid(){
#function safe-format-and-mount() {
#function unique-uuid-bind-mount(){
#function safe-bind-mount(){
#function mount-ext(){
#function ensure-local-ssds() {
#function setup-logrotate() {
#function find-master-pd {
#function mount-master-pd {
#function append_or_replace_prefixed_line {
#function write-pki-data {
#function create-node-pki {
#function create-master-pki {
#function create-master-auth {
#function create-master-audit-policy {
#function create-master-audit-webhook-config {
#function create-kubelet-kubeconfig() {
#function create-master-kubelet-auth {
#function create-kubeproxy-user-kubeconfig {
#function create-kubecontrollermanager-kubeconfig {
#function create-kubescheduler-kubeconfig {
#function create-clusterautoscaler-kubeconfig {
#function create-kubescheduler-policy-config {
#function create-node-problem-detector-kubeconfig {
#function create-master-etcd-auth {
#function assemble-docker-flags {
#function start-kubelet {
#function start-node-problem-detector {
#function prepare-log-file {
#function prepare-kube-proxy-manifest-variables {
#function start-kube-proxy {
#function prepare-etcd-manifest {
#function start-etcd-empty-dir-cleanup-pod {
#function start-etcd-servers {
#function compute-master-manifest-variables {
#function prepare-mounter-rootfs {
#function start-kube-apiserver {
#function setup-etcd-encryption {
#function apply-encryption-config() {
#function start-kube-controller-manager {
#function start-kube-scheduler {
#function start-cluster-autoscaler {
#function setup-addon-manifests {
#function download-extra-addons {
#function get-metadata-value {
#function copy-manifests {
#function wait-for-apiserver-and-update-fluentd {
#function start-fluentd-resource-update {
#function update-container-runtime {
#function update-node-journal {
#function update-prometheus-to-sd-parameters {
#function update-daemon-set-prometheus-to-sd-parameters {
#function update-event-exporter {
#function update-dashboard-controller {
#function setup-coredns-manifest {
#function setup-fluentd {
#function setup-kube-dns-manifest {
#function setup-netd-manifest {
#function setup-addon-custom-yaml {
#function start-kube-addons {
#function setup-node-termination-handler-manifest {
#function start-lb-controller {
#function setup-kubelet-dir {
#function gke-master-start {
#function reset-motd {
#function override-kubectl {
#function override-pv-recycler {

