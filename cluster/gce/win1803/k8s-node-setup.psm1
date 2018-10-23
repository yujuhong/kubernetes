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
$infraContainer = "kubeletwin/pause"
Export-ModuleMember -Variable infraContainer
$gceMetadataServer = "169.254.169.254"
# The name of the primary "physical" network adapter for the Windows VM.
$primaryNetAdapterName = "Ethernet"

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

# Fails and exits if the route to the GCE metadata server is not present,
# otherwise does nothing and emits nothing.
function Verify-GceMetadataServerRouteIsPresent {
  Try {
    Get-NetRoute -ErrorAction "Stop" -AddressFamily IPv4 `
      -DestinationPrefix ${gceMetadataServer}/32 | Out-Null
  } Catch [Microsoft.PowerShell.Cmdletization.Cim.CimJobException] {
    # TODO(pjh): add $true arg to make this fatal.
    Log "GCE metadata server route is not present as expected.`n$(Get-NetRoute -AddressFamily IPv4 | Out-String)"
  }
}

function WaitFor-GceMetadataServerRouteToBeRemoved {
  Log "Waiting for GCE metadata server route to be removed"
  while ($true) {
    Try {
      Get-NetRoute -ErrorAction "Stop" -AddressFamily IPv4 `
        -DestinationPrefix ${gceMetadataServer}/32 | Out-Null
    } Catch [Microsoft.PowerShell.Cmdletization.Cim.CimJobException] {
      break
    }
    Start-Sleep 2
    continue
  }
}

function Add-GceMetadataServerRoute {
  # Before setting up HNS the 1803 VM has a "vEthernet (nat)" interface and a
  # "Ethernet" interface, and the route to the metadata server exists on the
  # Ethernet interface. After adding the HNS network a "vEthernet (Ethernet)"
  # interface is added, and it seems to subsume the routes of the "Ethernet"
  # interface (trying to add routes on the Ethernet interface at this point just
  # results in "New-NetRoute : Element not found" errors). I don't know what's
  # up with that, but since it's hard to know what's the right thing to do here
  # we just try to add the route on all of the network adapters.
  Get-NetAdapter | ForEach-Object {
    $adapterIndex = $_.InterfaceIndex
    New-NetRoute -ErrorAction SilentlyContinue `
      -DestinationPrefix "${gceMetadataServer}/32" `
      -InterfaceIndex ${adapterIndex} | Out-Null
  }
  #route /p add ${gceMetadataServer} mask 255.255.255.255 0.0.0.0 if 4 metric 1
  #route add ${gceMetadataServer} mask 255.255.255.255 0.0.0.0
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
    "LOGS_DIR" = "${k8sDir}\logs"
    "CNI_DIR" = "${k8sDir}\cni"
    "CNI_CONFIG_DIR" = "${k8sDir}\cni\config"
    "KUBELET_CONFIG" = "${k8sDir}\kubelet-config.yaml"
    "KUBECONFIG" = "${k8sDir}\kubelet.kubeconfig"
    "BOOTSTRAP_KUBECONFIG" = "${k8sDir}\kubelet.bootstrap-kubeconfig"
    "KUBEPROXY_KUBECONFIG" = "${k8sDir}\kubeproxy.kubeconfig"
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
  docker build -t ${infraContainer} ${env:K8S_DIR}\pauseimage
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

  mkdir -Force ${env:CNI_CONFIG_DIR}
  $l2bridgeConf = "${env:CNI_CONFIG_DIR}\l2bridge.conf"
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
    Log "kubelet bootstrap kubeconfig:`n$(Get-Content -Raw ${env:BOOTSTRAP_KUBECONFIG})"
  } ElseIf (${fetchBootstrapConfig}) {
    NotImplemented "fetching kubelet bootstrap-kubeconfig file from metadata" `
      $true
    # get-metadata-value "instance/attributes/bootstrap-kubeconfig" >
    #   /var/lib/kubelet/bootstrap-kubeconfig
    Log "kubelet bootstrap kubeconfig:`n$(Get-Content -Raw ${env:BOOTSTRAP_KUBECONFIG})"
  } Else {
    NotImplemented "fetching kubelet kubeconfig file from metadata" $true
    # get-metadata-value "instance/attributes/kubeconfig" >
    #   /var/lib/kubelet/kubeconfig
    Get-Content -Raw ${env:KUBECONFIG}
    Log "kubelet kubeconfig:`n$(Get-Content -Raw ${env:KUBECONFIG})"
  }
}

# This is analogous to create-kubeproxy-user-kubeconfig() in
# gci/configure-helper.sh for Linux nodes. Create-NodePki() must be called
# first.
# Required ${kubeEnv} keys:
#   CA_CERT
#   KUBE_PROXY_TOKEN
function Create-KubeproxyKubeconfig() {
  # TODO: make this command and other New-Item commands silent.
  New-Item -ItemType file ${env:KUBEPROXY_KUBECONFIG}

  # In configure-helper.sh kubelet kubeconfig uses certificate-authority while
  # kubeproxy kubeconfig uses certificate-authority-data, ugh. Does it matter?
  # Use just one or the other for consistency?
  Set-Content ${env:KUBEPROXY_KUBECONFIG} `
'apiVersion: v1
kind: Config
users:
- name: kube-proxy
  user:
    token: KUBEPROXY_TOKEN
clusters:
- name: local
  cluster:
    certificate-authority-data: CA_CERT
contexts:
- context:
    cluster: local
    user: kube-proxy
  name: service-account-context
current-context: service-account-context'.`
    replace('KUBEPROXY_TOKEN', ${kubeEnv}['KUBE_PROXY_TOKEN']).`
    #replace('CA_CERT_BUNDLE_PATH', ${env:CA_CERT_BUNDLE_PATH})
    replace('CA_CERT', ${kubeEnv}['CA_CERT'])

  Log "kubeproxy kubeconfig:`n$(Get-Content -Raw ${env:KUBEPROXY_KUBECONFIG})"
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
    "--pod-infra-container-image=${infraContainer}",

    # Comes from https://github.com/Microsoft/SDN/blob/master/Kubernetes/windows/start-kubelet.ps1#L180:
    "--resolv-conf=`"`""

    # kubelet seems to fail (at least when running with bootstrap-kubeconfig)
    # when this flag is omitted. It's included at
    # https://github.com/Microsoft/SDN/blob/master/Kubernetes/windows/start-kubelet.ps1#L232.
    "--cgroups-per-qos=false"

    # kubelet seems to fail (at least when running with bootstrap-kubeconfig)
    # when this flag is omitted. It's included at
    # https://github.com/Microsoft/SDN/blob/master/Kubernetes/windows/start-kubelet.ps1#L232.
    "--enforce-node-allocatable=`"`""
  )

  # TODO(pjh): rename and use logs dir for these.
  $kubeletOut = "${env:NODE_DIR}\kubelet-out.txt"
  $kubeletErr = "${env:NODE_DIR}\kubelet-err.txt"

  # TODO(pjh): switch to Start-Job (for background processes) instead of
  # Start-Process here.
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

  Verify-GceMetadataServerRouteIsPresent

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
  Todo "update Configure-HostNetworkingService so that it checks for existing HNS network and overrides/removes it."
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
  # We wait until we're sure the route is gone (it does not disappear
  # immediately, it may take tens of seconds) before re-adding the route.
  Log "Waiting for HNS network to remove the GCE metadata server route"
  WaitFor-GceMetadataServerRouteToBeRemoved
  Log "Re-adding the GCE metadata server route"
  Add-GceMetadataServerRoute
  Verify-GceMetadataServerRouteIsPresent

  Log "Host network setup complete"
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
  # TODO(pjh): no idea if this HAIRPIN_MODE makes sense for Windows;
  # https://github.com/Microsoft/SDN/blob/master/Kubernetes/windows/start-kubelet.ps1#L231
  # uses promiscuous-bridge (as does my kubernetes-the-hard-way).
  # TODO(pjh): does cgroupRoot make sense for Windows?

  Log "Kubelet config:`n$(Get-Content -Raw ${env:KUBELET_CONFIG})"
}

function Start-WorkerServices {
  $kubeletArgsStr = ${kubeEnv}['KUBELET_ARGS']
  $kubeletArgs = $kubeletArgsStr.Split(" ")
  Log "kubeletArgs from metadata: ${kubeletArgs}"
    # --v=2
    # --allow-privileged=true
    # --cloud-provider=gce
    # --non-masquerade-cidr=0.0.0.0/0
    # --node-labels=beta.kubernetes.io/fluentd-ds-ready=true,cloud.google.com/gke-netd-ready=true

  # Reference:
  # https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/#options
  $additionalArgList = @(`
    "--config=${env:KUBELET_CONFIG}",
    "--kubeconfig=${env:KUBECONFIG}",

    # The directory where the TLS certs are located. If --tls-cert-file and
    # --tls-private-key-file are provided, this flag will be ignored.
    "--cert-dir=${env:PKI_DIR}",

    # The following flags are adapted from
    # https://github.com/Microsoft/SDN/blob/master/Kubernetes/windows/start-kubelet.ps1#L227:
    "--pod-infra-container-image=${infraContainer}",
    "--resolv-conf=`"`"",
    # The kubelet currently fails when this flag is omitted on Windows.
    "--cgroups-per-qos=false",
    # The kubelet currently fails when this flag is omitted on Windows.
    "--enforce-node-allocatable=`"`"",
    "--network-plugin=cni",
    "--cni-bin-dir=${env:CNI_DIR}",
    "--cni-conf-dir=${env:CNI_CONFIG_DIR}"

    # These flags come from Microsoft/SDN, not sure what they do or if
    # they're needed.
    # --log-dir=c:\k --logtostderr=false
    #"--enable-debugging-handlers",
    #"--image-pull-progress-deadline=20m",
  )
  $kubeletArgs = ${kubeletArgs} + ${additionalArgList}

  # These args are present in the Linux KUBELET_ARGS value of kube-env, but I
  # don't think we need them or they don't make sense on Windows.
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
    # The container runtime to use. Possible values: 'docker', 'rkt'. (default
    # "docker")
    "--container-runtime=docker"
  )

  # kubeproxy is started on Linux nodes using
  # kube-manifests/kubernetes/gci-trusty/kube-proxy.manifest, which is
  # generated by start-kube-proxy in configure-helper.sh and contains e.g.:
  #   kube-proxy --master=https://35.239.84.171
  #   --kubeconfig=/var/lib/kube-proxy/kubeconfig --cluster-cidr=10.64.0.0/14
  #   --resource-container="" --oom-score-adj=-998 --v=2
  #   --feature-gates=ExperimentalCriticalPodAnnotation=true
  #   --iptables-sync-period=1m --iptables-min-sync-period=10s
  #   --ipvs-sync-period=1m --ipvs-min-sync-period=10s
  # And also with various volumeMounts and "securityContext: privileged: true".
  $apiserverAddress = ${kubeEnv}['KUBERNETES_MASTER_NAME']
  $kubeproxyArgs = @(`
    "--v=4",
    "--master=https://${apiserverAddress}",
    "--kubeconfig=${env:KUBEPROXY_KUBECONFIG}",
    "--proxy-mode=kernelspace",
    "--hostname-override=$(hostname)",
    "--resource-container=`"`"",
    "--cluster-cidr=$(${kubeEnv}['CLUSTER_IP_RANGE'])"
  )

  # TODO(pjh): move to prerequisites function.
  mkdir -Force ${env:LOGS_DIR}

  Log "Starting kubelet"

  # Use Start-Process, not Start-Job; jobs are killed as soon as the shell /
  # script that invoked them terminates, whereas processes continue running.
  #
  # -PassThru causes a process object to be returned from the Start-Process
  # command.
  #
  # TODO(pjh): add -UseNewEnvironment flag and debug error "server.go:262]
  # failed to run Kubelet: could not init cloud provider "gce": Get
  # http://169.254.169.254/computeMetadata/v1/instance/zone: dial tcp
  # 169.254.169.254:80: socket: The requested service provider could not be
  # loaded or initialized."
  # -UseNewEnvironment ensures that there are no implicit dependencies
  # on the variables in this script - everything the kubelet needs should be
  # specified via flags or config files.
  $kubeletProcess = Start-Process `
    -FilePath "${env:NODE_DIR}\kubelet.exe" `
    -ArgumentList ${kubeletArgs} `
    -WindowStyle Hidden -PassThru `
    -RedirectStandardOutput ${env:LOGS_DIR}\kubelet.out `
    -RedirectStandardError ${env:LOGS_DIR}\kubelet.log
  Log "$(${kubeletProcess} | Out-String)"
  # TODO(pjh): set kubeletProcess as a global variable so that
  # Stop-WorkerServices can access it.

  Log "Waiting 10 seconds for kubelet to stabilize"
  Start-Sleep 10

  # F1020 23:08:52.000083    9136 server.go:361] unable to load in-cluster
  # configuration, KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT must be
  # defined
  Log "Starting kube-proxy"
  $kubeproxyProcess = Start-Process `
    -FilePath "${env:NODE_DIR}\kube-proxy.exe" `
    -ArgumentList ${kubeproxyArgs} `
    -WindowStyle Hidden -PassThru `
    -RedirectStandardOutput ${env:LOGS_DIR}\kube-proxy.out `
    -RedirectStandardError ${env:LOGS_DIR}\kube-proxy.log
  Log "$(${kubeproxyProcess} | Out-String)"

  # TODO(pjh): still getting errors like these in kube-proxy log:
  # E1023 04:03:58.143449    4840 reflector.go:205] k8s.io/kubernetes/pkg/client/informers/informers_generated/internalversion/factory.go:129: Failed to list *core.Endpoints: Get https://35.239.84.171/api/v1/endpoints?limit=500&resourceVersion=0: dial tcp 35.239.84.171:443: connectex: A connection attempt failed because the connected party did not properly respond after a period of time, or established connection failed because connected host has failed to respond.
  # E1023 04:03:58.150266    4840 reflector.go:205] k8s.io/kubernetes/pkg/client/informers/informers_generated/internalversion/factory.go:129: Failed to list *core.Service: Get https://35.239.84.171/api/v1/services?limit=500&resourceVersion=0: dial tcp 35.239.84.171:443: connectex: A connection attempt failed because the connected party did not properly respond after a period of time, or established connection failed because connected host has failed to respond.

  Todo "verify that jobs are still running; print more details about the background jobs."
  Log "$(Get-Process kube* | Out-String)"
  Verify-GceMetadataServerRouteIsPresent
  Log "Kubernetes components started successfully"
}

function Stop-WorkerServices {
  # Stop-Job
  # Remove-Job
}

function Verify-WorkerServices {
  Log "kubectl get nodes:`n$(& ${env:NODE_DIR}\kubectl.exe get nodes | Out-String)"
  Verify-GceMetadataServerRouteIsPresent
  Todo "run more verification commands."
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
Export-ModuleMember -Function Create-KubeproxyKubeconfig
Export-ModuleMember -Function Get-PodCidr
Export-ModuleMember -Function RunKubeletOnceToGet-PodCidr
Export-ModuleMember -Function Configure-HostNetworkingService
Export-ModuleMember -Function Configure-Kubelet
Export-ModuleMember -Function Start-WorkerServices
Export-ModuleMember -Function Stop-WorkerServices
Export-ModuleMember -Function Verify-WorkerServices
