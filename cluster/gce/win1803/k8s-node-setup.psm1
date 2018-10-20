# TODO: copyright / license statement.

# Some portions copied / adapter from
# https://github.com/Microsoft/SDN/blob/master/Kubernetes/windows/start-kubelet.ps1

# Suggested usage for dev/test:
#   [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
#   Invoke-WebRequest https://github.com/pjh/kubernetes/raw/windows-up/cluster/gce/win1803/k8s-node-setup.psm1 -OutFile k8s-node-setup.psm1
#   Invoke-WebRequest https://github.com/pjh/kubernetes/raw/windows-up/cluster/gce/win1803/configure.ps1 -OutFile configure.ps1
#   Import-Module -Force .\k8s-node-setup.psm1  # -Force to override existing
#   # Execute functions manually or run configure.ps1.

$k8sDir = "C:\etc\kubernetes"
Export-ModuleMember -Variable k8sDir

function Log {
  param (
    [parameter(Mandatory=$true)] [string]$message,
    [parameter(Mandatory=$false)] [bool]$fail = $false
  )
  # TODO(pjh): what's correct, Write-Output or Write-Host??
  Write-Output "${message}"
  If (${fail}) {
    Exit 1
  }
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
  Log "Not implemented yet: ${message}" ${fail}
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
#
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
  $kubeEnv = Get-MetadataValue 'kube-env'
  $kubeEnvTable = ConvertFrom-Yaml ${kubeEnv}

  # TODO(pjh): instead of returning kubeEnvTable, put it in $global namespace
  # so it's accessible from all other functions?
  return ${kubeEnvTable}
}

function Set-MachineEnvironmentVar {
  param (
    [parameter(Mandatory=$true)] [string]$key,
    [parameter(Mandatory=$true)] [string]$value
  )
  [Environment]::SetEnvironmentVariable($key, $value, "Machine")
}

function Set-CurrentShellEnvironmentVar {
  param (
    [parameter(Mandatory=$true)] [string]$key,
    [parameter(Mandatory=$true)] [string]$value
  )
  $expression = -join('$env:', $key, ' = "', $value, '"')
  Invoke-Expression ${expression}
}

function Set-EnvironmentVars {
  $envVars = @{
    "K8S_DIR" = "${k8sDir}"
    "NODE_DIR" = "${k8sDir}\node"
    "Path" = ${env:Path} + ";${k8sDir}\node"
    "CNI_DIR" = "${k8sDir}\cni"
    "KUBELET_CONFIG" = "${k8sDir}\kubelet-config.yaml"
    "KUBECONFIG" = "${k8sDir}\kubelet.kubeconfig"
    "BOOTSTRAP_KUBECONFIG" = "${k8sDir}\kubelet.bootstrap-kubeconfig"
    "KUBE_NETWORK" = "l2bridge"
    "PKI_DIR" = "${k8sDir}\pki"
    "CA_CERT_BUNDLE_PATH" = "${k8sDir}\pki\ca-certificates.crt"
    "KUBELET_CERT_PATH" = "${k8sDir}\pki\kubelet.crt"
    "KUBELET_KEY_PATH" = "${k8sDir}\pki\kubelet.key"
  }

  # Set the environment variables in two ways: permanently on the machine (only
  # takes effect after a reboot), and in the current shell.
  $envVars.GetEnumerator() | ForEach-Object{
    $message = -join("Setting environment variable: ", $_.key, " = ",`
                     $_.value)
    Write-Output ${message}
    Set-MachineEnvironmentVar $_.key $_.value
    Set-CurrentShellEnvironmentVar $_.key $_.value
  }
}

function Set-PrerequisiteOptions {
  # Disable Windows firewall.
  Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False
  # Use TLS 1.2: needed for Invoke-WebRequest to github.com.
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  Todo "disable automatic Windows Updates and restarts"

  # https://github.com/cloudbase/powershell-yaml
  Log "installing powershell-yaml module from external repo"
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

# TODO(pjh): this is copied from
# https://github.com/Microsoft/SDN/blob/master/Kubernetes/windows/start-kubelet.ps1#L98.
# See if there's a way to fetch or construct the "management subnet" so that
# this os not needed.
function
ConvertTo-DecimalIP
{
  param(
    [Parameter(Mandatory = $true, Position = 0)]
    [Net.IPAddress] $IPAddress
  )
  $i = 3; $DecimalIP = 0;
  $IPAddress.GetAddressBytes() | % {
    $DecimalIP += $_ * [Math]::Pow(256, $i); $i--
  }

  return [UInt32]$DecimalIP
}

# TODO(pjh): this is copied from
# https://github.com/Microsoft/SDN/blob/master/Kubernetes/windows/start-kubelet.ps1#L98.
# See if there's a way to fetch or construct the "management subnet" so that
# this os not needed.
function
ConvertTo-DottedDecimalIP
{
  param(
    [Parameter(Mandatory = $true, Position = 0)]
    [Uint32] $IPAddress
  )

    $DottedIP = $(for ($i = 3; $i -gt -1; $i--)
    {
      $Remainder = $IPAddress % [Math]::Pow(256, $i)
      ($IPAddress - $Remainder) / [Math]::Pow(256, $i)
      $IPAddress = $Remainder
    })

    return [String]::Join(".", $DottedIP)
}

# TODO(pjh): this is copied from
# https://github.com/Microsoft/SDN/blob/master/Kubernetes/windows/start-kubelet.ps1#L98.
# See if there's a way to fetch or construct the "management subnet" so that
# this os not needed.
function
ConvertTo-MaskLength
{
  param(
    [Parameter(Mandatory = $True, Position = 0)]
    [Net.IPAddress] $SubnetMask
  )
    $Bits = "$($SubnetMask.GetAddressBytes() | % {
      [Convert]::ToString($_, 2)
    } )" -replace "[\s0]"
    return $Bits.Length
}

# TODO(pjh): copied from
# https://github.com/Microsoft/SDN/blob/master/Kubernetes/windows/start-kubelet.ps1#L98.
# Not sure what the "Management subnet" is or why this function works the way
# it does.
#
# TODO(pjh): update this to return both $addr as well as $mgmtSubnet.
function Get-MgmtSubnet {
  # TODO(pjh): make "vEthernet (nat*" a constant somewhere.
  $netAdapter = Get-NetAdapter | Where-Object Name -Like "vEthernet (nat*"
  if (!${netAdapter}) {
    throw "Failed to find a suitable network adapter, check your network settings."
  }

  $addr = (Get-NetIPAddress -InterfaceAlias ${netAdapter}.ifAlias `
    -AddressFamily IPv4).IPAddress
  $mask = (Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object `
    InterfaceIndex -eq $(${netAdapter}.ifIndex)).IPSubnet[0]
  $mgmtSubnet = `
    (ConvertTo-DecimalIP ${addr}) -band (ConvertTo-DecimalIP ${mask})
  $mgmtSubnet = ConvertTo-DottedDecimalIP ${mgmtSubnet}
  return "${mgmtSubnet}/$(ConvertTo-MaskLength $mask)"
}

function Configure-CniNetworking {
  # TODO(pjh): create all necessary dirs up-front in a separate function?
  mkdir -Force ${env:CNI_DIR}
  Invoke-WebRequest `
    https://github.com/Microsoft/SDN/raw/master/Kubernetes/windows/cni/wincni.exe `
    -OutFile ${env:CNI_DIR}\wincni.exe

  $vethIp = (Get-NetAdapter | Where-Object Name -Like "vEthernet (nat*" |`
    Get-NetIPAddress -AddressFamily IPv4).IPAddress
  $mgmtSubnet = Get-MgmtSubnet
  Log "using mgmt IP ${vethIp} and mgmt subnet ${mgmtSubnet} for CNI config"

  mkdir -Force ${env:CNI_DIR}\config
  $l2bridgeConf = "${env:CNI_DIR}\config\l2bridge.conf"
  # TODO(pjh): add -Force to overwrite if exists? Or do we want to fail?
  New-Item -ItemType file ${l2bridgeConf}

  Todo "switch to using win-bridge plugin instead of wincni and update l2bridge.conf if needed."
  # https://github.com/containernetworking/plugins/tree/master/plugins/main/windows/win-bridge

  # TODO(pjh): validate these values against CNI config on Linux node.
  #
  # Explanation of the CNI config values:
  #   DNS_SERVER_IP: ...
  #   DNS_DOMAIN: ...
  #   CLUSTER_CIDR: TODO: validate this against Linux kube-proxy-config.yaml.
  #   SERVER_CIDR: SERVICE_CLUSTER_IP_RANGE from kubeEnv?
  #   MGMT_SUBNET: $mgmtSubnet.
  #   MGMT_IP: $vethIp.
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
      "DNS_SERVER_IP"
    ],
    "Search": [
      "DNS_DOMAIN"
    ]
  },
  "AdditionalArgs":  [
    {
      "Name":  "EndpointPolicy",
      "Value":  {
        "Type":  "OutBoundNAT",
        "ExceptionList":  [
          CLUSTER_CIDR,
          SERVER_CIDR,
          MGMT_SUBNET
        ]
      }
    },
    {
      "Name":  "EndpointPolicy",
      "Value":  {
        "Type":  "ROUTE",
        "DestinationPrefix":  "SERVER_CIDR",
        "NeedEncap":  true
      }
    },
    {
      "Name":  "EndpointPolicy",
      "Value":  {
        "Type":  "ROUTE",
        "DestinationPrefix":  "MGMT_IP/32",
        "NeedEncap":  true
      }
    }
  ]
}'.replace('DNS_SERVER_IP', ${kubeEnv}['DNS_SERVER_IP']).`
  replace('DNS_DOMAIN', ${kubeEnv}['DNS_DOMAIN']).`
  replace('MGMT_IP', ${vethIp}).`
  replace('CLUSTER_CIDR', ${kubeEnv}['CLUSTER_IP_RANGE']).`
  replace('SERVER_CIDR', ${kubeEnv}['SERVICE_CLUSTER_IP_RANGE']).`
  replace('MGMT_SUBNET', ${mgmtSubnet})

  Log "CNI config:`n$(Get-Content -Raw ${l2bridgeConf})"
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
  Todo "need to set permissions correctly on ${file}; not sure what the Windows equivalent of 'umask 077' is"
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
  # think. cluster/gce/gci/configure-helper.sh?l=2801
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
    Get-Content -Raw ${env:BOOTSTRAP_KUBECONFIG}
  } ElseIf (${fetchBootstrapConfig}) {
    NotImplemented "fetching kubelet bootstrap-kubeconfig file from metadata" `
      $true
    # get-metadata-value "instance/attributes/bootstrap-kubeconfig" >
    #   /var/lib/kubelet/bootstrap-kubeconfig
    Get-Content -Raw ${env:BOOTSTRAP_KUBECONFIG}
  } Else {
    NotImplemented "fetching kubelet kubeconfig file from metadata" $true
    # get-metadata-value "instance/attributes/kubeconfig" >
    #   /var/lib/kubelet/kubeconfig
    Get-Content -Raw ${env:KUBECONFIG}
  }
}

function Get-PodCidr {
  # TODO(pjh): fail if errors detected here. For example, if bootstrap process
  # didn't generate permanent kubeconfig correctly, kubectl execution will
  # return "error: CreateFile C:\etc\kubernetes\kubelet.kubeconfig: The system
  # cannot find the file specified", and we'll never successfully get the
  # podCidr.
  $podCidr = & ${env:NODE_DIR}\kubectl.exe --kubeconfig=${env:KUBECONFIG} `
    get nodes/$($(hostname).ToLower()) `
    -o custom-columns=podCidr:.spec.podCIDR --no-headers
  # TODO(pjh): I read somewhere that return statement isn't necessary at the
  # end of functions in PowerShell; review this and update script accordingly.
  return $podCidr
}

# This function runs the kubelet until it registers with the master, then kills
# it. The main reason for doing this is that it causes a pod CIDR to be
# assigned to this node. Additionally, the kubelet will consume the bootstrap
# kubeconfig and write out the permanent kubeconfig.
#
# The pod CIDR can be accessed at $env:POD_CIDR after this function returns.
function RunKubeletOnceToGet-PodCidr {
  # Linux node path is something like
  # (cluster/gce/gci/configure-helper.sh?l=2760):
  # - Set KUBELET_CONFIG_FILE_ARG by fetching kubelet-config metadata value and
  #   storing it in ${KUBE_HOME}/kubelet-config.yaml.
  # - setup-os-params, config-ip-firewall, create-dirs, setup-kubelet-dir,
  #   ensure-local-ssds, setup-logrotate, create-node-pki (done!),
  #   create-kubelet-kubeconfig (done!), create-kubeproxy-user-kubeconfig,
  #   create-node-problem-detector-kubeconfig
  # - override-kubectl
  #   wtf? cluster/gce/gci/configure-helper.sh?l=2698
  # - assemble-docker-flags: "Run the containerized mounter once to pre-cache
  #   the container image"
  #     -p /var/run/docker.pid --iptables=false --ip-masq=false
  #     and either --bip=169.254.123.1/24 or --bridge=cbr0
  # - start-kubelet
  #
  # TODO: ignore all of this for now. Try the approach used in the Microsoft
  # scripts of connecting the kubelet to the master once to get a podCidr, then
  # killing the kubelet, configuring HNS and further kubelet / kubeproxy stuff,
  # then starting kubelet and kubeproxy again. Looks like you may not need
  # the "kubelet config" for the first kubelet run, only the "kubeconfig"; try
  # running with the bootstrap config specified and see what happens

  $argListForFirstKubeletRun = @(`
    "--v=2",

    # Path to a kubeconfig file that will be used to get client certificate for
    # kubelet. If the file specified by --kubeconfig does not exist, the
    # bootstrap kubeconfig is used to request a client certificate from the API
    # server. On success, a kubeconfig file referencing the generated client
    # certificate and key is written to the path specified by --kubeconfig. The
    # client certificate and key file will be stored in the directory pointed
    # by --cert-dir.
    #
    # See also:
    # https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet-tls-bootstrapping/
    "--bootstrap-kubeconfig=${env:BOOTSTRAP_KUBECONFIG}",
    "--kubeconfig=${env:KUBECONFIG}",

    # The directory where the TLS certs are located. If --tls-cert-file and
    # --tls-private-key-file are provided, this flag will be ignored.
    "--cert-dir=${env:PKI_DIR}",

    # Comes from https://github.com/Microsoft/SDN/blob/master/Kubernetes/windows/start-kubelet.ps1#L180:
    "--pod-infra-container-image=kubeletwin/pause",

    # Comes from https://github.com/Microsoft/SDN/blob/master/Kubernetes/windows/start-kubelet.ps1#L180:
    "--resolv-conf="""""

    # kubelet seems to fail (at least when running with bootstrap-kubeconfig)
    # when this flag is omitted. It's included at
    # https://github.com/Microsoft/SDN/blob/master/Kubernetes/windows/start-kubelet.ps1#L232.
    "--cgroups-per-qos=false"

    # kubelet seems to fail (at least when running with bootstrap-kubeconfig)
    # when this flag is omitted. It's included at
    # https://github.com/Microsoft/SDN/blob/master/Kubernetes/windows/start-kubelet.ps1#L232.
    "--enforce-node-allocatable=`"`""
  )

  # Notable kubelet log messages when running with the flags above:
  # W1015 16:24:58.896270     760 cni.go:172] Unable to update cni config: No networks found in /etc/cni/net.d
  # I1015 16:24:58.907054     760 docker_service.go:253] Docker cri networking managed by kubernetes.io/no-op
  # E1015 16:25:00.075959     760 kubelet_network.go:102] Failed to ensure that nat chain KUBE-MARK-DROP exists: error creating chain "KUBE-MARK-DROP": executable file not found in %PATH%:
  # I1015 16:25:00.179487     760 kubelet_node_status.go:79] Attempting to register node kubernetes-minion-windows-group-ccr3
  # I1015 16:25:00.186306     760 kubelet_node_status.go:82] Successfully registered node kubernetes-minion-windows-group-ccr3
  # I1015 16:25:10.203846     760 kuberuntime_manager.go:917] updating runtime config through cri with podcidr 10.64.3.0/24
  # I1015 16:25:10.204822     760 docker_service.go:352] docker cri received runtime config &RuntimeConfig{NetworkConfig:                   &NetworkConfig{PodCidr:10.64.3.0/24,},}
  # I1015 16:25:10.209715     760 kubelet_network.go:73] Setting Pod CIDR:  -> 10.64.3.0/24
  #
  # kubeconfig that gets generated:
  #   apiVersion: v1
  #   clusters:
  #   - cluster:
  #       certificate-authority: C:\etc\kubernetes\pki\ca-certificates.crt
  #       server: https://35.232.38.37
  #     name: default-cluster
  #   contexts:
  #   - context:
  #       cluster: default-cluster
  #       namespace: default
  #       user: default-auth
  #     name: default-context
  #   current-context: default-context
  #   kind: Config
  #   preferences: {}
  #   users:
  #   - name: default-auth
  #     user:
  #       client-certificate: C:\etc\kubernetes\pki\kubelet-client-current.pem
  #       client-key: C:\etc\kubernetes\pki\kubelet-client-current.pem
  #
  # C:\etc\kubernetes\node\kubectl.exe --kubeconfig=C:\etc\kubernetes\kubelet.kubeconfig get nodes
  # NAME                                   STATUS                     ROLES     AGE       VERSION
  # kubernetes-master                      Ready,SchedulingDisabled   <none>    4d20h     v1.13.0-alpha.0.2025+01f8948e809e94-dirty
  # kubernetes-minion-group-svgq           Ready                      <none>    4d20h     v1.13.0-alpha.0.2025+01f8948e809e94-dirty
  # kubernetes-minion-group-v3gm           Ready                      <none>    4d20h     v1.13.0-alpha.0.2025+01f8948e809e94-dirty
  # kubernetes-minion-windows-group-ccr3   Ready                      <none>    29h       v1.11.3
  #
  # C:\etc\kubernetes\node\kubectl.exe --kubeconfig=C:\etc\kubernetes\kubelet.kubeconfig get nodes/$($(hostname).ToLower()) -o custom-columns=podCidr:.spec.podCIDR --no-headers
  # 10.64.3.0/24
  #
  # Woohoo!

  $kubeletOut = "${env:NODE_DIR}\kubelet-out.txt"
  $kubeletErr = "${env:NODE_DIR}\kubelet-err.txt"

  $kubeletProcess = Start-Process -FilePath ${env:NODE_DIR}\kubelet.exe `
    -PassThru -ArgumentList ${argListForFirstKubeletRun} `
    -RedirectStandardOutput $kubeletOut `
    -RedirectStandardError $kubeletErr

  $podCidr = ""
  while (${podCidr}.length -eq 0) {
    Write-Output "Waiting for kubelet to fetch pod CIDR"
    Start-Sleep -sec 5
    ${podCidr} = Get-PodCidr
  }
  # Stop the kubelet process.
  ${kubeletProcess} | Stop-Process

  Write-Output "fetched pod CIDR: ${podCidr}"
  Set-MachineEnvironmentVar "POD_CIDR" ${podCidr}
  Set-CurrentShellEnvironmentVar "POD_CIDR" ${podCidr}
}

function Configure-HostNetworkingService {
  $endpointName = "cbr0"
  $vnicName = "vEthernet (${endpointName})"

  # TODO: move this to install-prerequisites method.
  Invoke-WebRequest `
    https://github.com/Microsoft/SDN/raw/master/Kubernetes/windows/hns.psm1 `
    -OutFile ${env:K8S_DIR}\hns.psm1
  Import-Module -Force ${env:K8S_DIR}\hns.psm1

  # For Windows nodes the pod gateway IP address is the .1 address in the pod
  # CIDR for the host, but from inside containers it's the .2 address.
  $podGateway = `
    ${env:POD_CIDR}.substring(0, ${env:POD_CIDR}.lastIndexOf('.')) + '.1'
  $podEndpointGateway = `
    ${env:POD_CIDR}.substring(0, ${env:POD_CIDR}.lastIndexOf('.')) + '.2'
  Log "Setting up Windows node HNS networking: podCidr = ${env:POD_CIDR}, podGateway = ${podGateway}, podEndpointGateway = ${podEndpointGateway}"

  # Note: RDP connection will hiccup when running this command.
  New-HNSNetwork -Type "L2Bridge" -AddressPrefix ${env:POD_CIDR} `
    -Gateway ${podGateway} -Name ${env:KUBE_NETWORK} -Verbose
  $hnsNetwork = Get-HnsNetwork | ? Type -EQ "L2Bridge"
  $hnsEndpoint = New-HnsEndpoint -NetworkId ${hnsNetwork}.Id `
    -Name ${endpointName} -IPAddress ${podEndpointGateway} `
    -Gateway "0.0.0.0" -Verbose
  Attach-HnsHostEndpoint -EndpointID ${hnsEndpoint}.Id -CompartmentID 1 -Verbose
  netsh interface ipv4 set interface "${vnicName}" forwarding=enabled
  Get-HNSPolicyList | Remove-HnsPolicyList

  # Workaround for
  # https://github.com/Microsoft/hcsshim/issues/299#issuecomment-425491610:
  # re-add the route to the GCE metadata server after creating the HNS network.
  # The route does not seem to disappear immediately, so sleep for a bit.
  Log "Waiting 10 seconds for routes to stabilize after HNS network creation"
  Start-Sleep 10
  $gceMetadataServer = "169.254.169.254"
  route /p add ${gceMetadataServer} mask 255.255.255.255 0.0.0.0

  Log "Host network setup complete"
}

# This is what the KubeletConfiguration looked like for kubernetes-the-hard-way.
# TODO: remove this.
function Configure-KubeletTheHardWay {
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
tlsPrivateKeyFile: "K8S_DIR\HOSTNAME-key.pem"'.`
  replace('K8S_DIR', ${env:K8S_DIR}).`
  replace('POD_CIDR', ${podCidr}).`
  replace('HOSTNAME', $(hostname)).`
  replace('\', '\\')
}

function Configure-Kubelet {
  # Linux node: /home/kubernetes/kubelet-config.yaml is built by
  # build-kubelet-config() in util.sh, then posted to metadata server as
  # kubelet-config.
  Todo "building KubeletConfiguration; for Linux nodes this is done by the cluster scripts and posted to metadata server. Do the same for Windows?"

  Set-Content ${env:KUBELET_CONFIG} `
'kind: KubeletConfiguration
apiVersion: kubelet.config.k8s.io/v1beta1
cgroupRoot: /
clusterDNS:
  - "DNS_SERVER_IP"
clusterDomain: "DNS_DOMAIN"
staticPodPath: STATIC_POD_PATH
readOnlyPort: 10255
enableDebuggingHandlers: true
authentication:
  x509:
    clientCAFile: CLIENT_CA_FILE
hairpinMode: "HAIRPIN_MODE"
evictionHard:
  memory.available: "250Mi"
  nodefs.available: "10%"
  nodefs.inodesFree: "5%"
featureGates:
  ExperimentalCriticalPodAnnotation: true'.`
  replace('DNS_SERVER_IP', ${kubeEnv}['DNS_SERVER_IP']).`
  replace('DNS_DOMAIN', ${kubeEnv}['DNS_DOMAIN']).`
  replace('STATIC_POD_PATH', ${env:K8S_DIR}).`
  replace('CLIENT_CA_FILE', ${env:CA_CERT_BUNDLE_PATH}).`
  replace('HAIRPIN_MODE', 'hairpin-veth')
  # TODO(pjh): STATIC_POD_PATH is /etc/kubernetes/manifests on Linux, no idea
  # what makes sense for Windows.
  # TODO(pjh): no idea if this HAIRPIN_MODE makes sense for Windows.

  Log "Kubelet config:`n$(Get-Content -Raw ${env:KUBELET_CONFIG})"
}

function Start-WorkerServices {
  # https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/#options
  Todo "switch to using KUBELET_ARGS instead of building them here."
  $kubeletArgs = ${kubeEnv}['KUBELET_ARGS']
  Log "kubeletArgs from metadata: ${kubeletArgs}"

  # TODO: dedup $kubeletArgs and argList
  $argList = @(`
    "--v=2",
    "--allow-privileged=true",
    "--cloud-provider=gce",

    # Path to a kubeconfig file that will be used to get client certificate for
    # kubelet. If the file specified by --kubeconfig does not exist, the
    # bootstrap kubeconfig is used to request a client certificate from the API
    # server. On success, a kubeconfig file referencing the generated client
    # certificate and key is written to the path specified by --kubeconfig. The
    # client certificate and key file will be stored in the directory pointed
    # by --cert-dir.
    #
    # See also:
    # https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet-tls-bootstrapping/
    #"--bootstrap-kubeconfig=${env:BOOTSTRAP_KUBECONFIG}",
    "--kubeconfig=${env:KUBECONFIG}",

    # The directory where the TLS certs are located. If --tls-cert-file and
    # --tls-private-key-file are provided, this flag will be ignored.
    "--cert-dir=${env:PKI_DIR}",

    # TODO(pjh): necessary on Windows?
    "--cni-bin-dir=${env:CNI_DIR}",
    "--network-plugin=cni",

    # TODO: what is this?
    "--non-masquerade-cidr=0.0.0.0/0",

    # Comes from https://github.com/Microsoft/SDN/blob/master/Kubernetes/windows/start-kubelet.ps1#L180:
    "--pod-infra-container-image=kubeletwin/pause",

    # Comes from https://github.com/Microsoft/SDN/blob/master/Kubernetes/windows/start-kubelet.ps1#L180:
    "--resolv-conf="""""
  )

  # These args are present in the KUBELET_ARGS value of kube-env, but I don't
  # think we need them or they don't make sense on Windows.
  $argListUnused = @(`
    # [Experimental] Path of mounter binary. Leave empty to use the default
    # mount.
    "--experimental-mounter-path=/home/kubernetes/containerized_mounter/mounter",
    # [Experimental] if set true, the kubelet will check the underlying node
    # for required components (binaries, etc.) before performing the mount
    "--experimental-check-node-capabilities-before-mount=true",
    # The Kubelet will use this directory for checkpointing downloaded
    # configurations and tracking configuration health. The Kubelet will create
    # this directory if it does not already exist. The path may be absolute or
    # relative; relative paths start at the Kubelet's current working
    # directory. Providing this flag enables dynamic Kubelet configuration.
    # Presently, you must also enable the DynamicKubeletConfig feature gate to
    # pass this flag.
    "--dynamic-config-dir=/var/lib/kubelet/dynamic-config",
    # The full path of the directory in which to search for additional third
    # party volume plugins (default
    # "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/")
    "--volume-plugin-dir=/home/kubernetes/flexvolume",
    # TODO(pjh): what node-labels do Windows nodes need?
    "--node-labels=beta.kubernetes.io/fluentd-ds-ready=true,cloud.google.com/gke-netd-ready=true",
    # The container runtime to use. Possible values: 'docker', 'rkt'. (default
    # "docker")
    "--container-runtime=docker"
  )

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

Export-ModuleMember -Function Log
Export-ModuleMember -Function Todo
Export-ModuleMember -Function NotImplemented
Export-ModuleMember -Function Get-MetadataValue
Export-ModuleMember -Function Download-KubeEnv
Export-ModuleMember -Function Set-MachineEnvironmentVar
Export-ModuleMember -Function Set-CurrentShellEnvironmentVar
Export-ModuleMember -Function Set-EnvironmentVars
Export-ModuleMember -Function Set-PrerequisiteOptions
Export-ModuleMember -Function Create-PauseImage
Export-ModuleMember -Function DownloadAndInstall-KubernetesBinaries
Export-ModuleMember -Function Get-MgmtSubnet
Export-ModuleMember -Function Configure-CniNetworking
Export-ModuleMember -Function Create-NodePki
Export-ModuleMember -Function Create-KubeletKubeconfig
Export-ModuleMember -Function Get-PodCidr
Export-ModuleMember -Function RunKubeletOnceToGet-PodCidr
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

