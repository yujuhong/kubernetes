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

# Installs open-ssh using the instructions in
# https://github.com/PowerShell/Win32-OpenSSH/wiki/Install-Win32-OpenSSH.
#
# After installation run StartProcess-WriteSshKeys to fetch ssh keys from the
# metadata server.
function InstallAndStart-OpenSSH{
  # Download open-ssh.
  $url = "https://github.com/PowerShell/Win32-OpenSSH/releases/download/v7.7.2.0p1-Beta/OpenSSH-Win32.zip"
  $ProgressPreference = 'SilentlyContinue'
  Invoke-WebRequest $url -OutFile C:\openssh-win32.zip

  # Unzip and install open-ssh
  Expand-Archive c:\openssh-win32.zip -DestinationPath "C:\Program Files\OpenSSH"
  powershell.exe -ExecutionPolicy Bypass -File "C:\Program Files\OpenSSH\OpenSSH-Win32\install-sshd.ps1"

  # Disable password-based authentication.
  $sshd_config_default="C:\Program Files\OpenSSH\OpenSSH-Win32\sshd_config_default"
  $sshd_config="C:\ProgramData\ssh\sshd_config"
  New-Item -ItemType Directory -Force -Path "C:\ProgramData\ssh\"
  # SSH config files must be UTF-8 encoded:
  # https://github.com/PowerShell/Win32-OpenSSH/issues/862
  # https://github.com/PowerShell/Win32-OpenSSH/wiki/Various-Considerations
  (Get-Content $sshd_config_default).replace('#PasswordAuthentication yes', 'PasswordAuthentication no') `
  | Set-Content -Encoding UTF8 $sshd_config

  # Configure the firewall to allow inbound SSH connections
  New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22

  # Start the services and configure them to automatically start on subsequent
  # boots:
  ForEach ($service in ("sshd", "ssh-agent")) {
    net start ${service}
    Set-Service ${service} -StartupType Automatic
  }
}

# Starts a background process that retrieves ssh keys from the metadata server
# and writes them to user-specific directories. Intended for use only by test
# clusters!!
#
# While this is running it should be possible to SSH to the Windows node using:
#   gcloud compute ssh <username>@<instance> --zone=<zone>
# or:
#   ssh -i ~/.ssh/google_compute_engine -o 'IdentitiesOnly yes' \
#     <username>@<instance_external_ip>
# or copy files using:
#   gcloud compute scp <username>@<instance>:C:\\path\\to\\file.txt \
#     path/to/destination/ --zone=<zone>
#
# If the username you're using does not already have a project-level SSH key
# (run "gcloud compute project-info describe --flatten
# commonInstanceMetadata.items.ssh-keys" to check), run gcloud compute ssh with
# that username once to add a new project-level SSH key, wait one minute for
# StartProcess-WriteSshKeys to pick it up, then try to ssh/scp again.
function StartProcess-WriteSshKeys{
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  Invoke-WebRequest `
    https://gist.githubusercontent.com/pjh/9753cd14400f4e3d4567f4553ba75f1d/raw/cb7929fa78fc8f840819249785e69838f3e35d64/user-profile.psm1 `
    -OutFile C:\user-profile.psm1

  $writeSshKeys = "C:\write-ssh-keys.ps1"
  New-Item -ItemType file -Force ${writeSshKeys}
  Set-Content ${writeSshKeys} `
'Import-Module C:\user-profile.psm1
# For [System.Web.Security.Membership]::GeneratePassword():
Add-Type -AssemblyName System.Web

$pollInterval = 10

while($true) {
  $r1 = ""
  $r2 = ""
  # Try both the new "ssh-keys" and the legacy "sshSkeys" attributes for
  # compatibility. The Invoke-RestMethods calls will fail when these attributes
  # do not exist, or they may fail when the connection to the metadata server
  # gets disrupted while we set up container networking on the node.
  try {
    $r1 = Invoke-RestMethod -Headers @{"Metadata-Flavor"="Google"} -Uri `
      "http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys"
  } catch {}
  try {
    $r2 = Invoke-RestMethod -Headers @{"Metadata-Flavor"="Google"} -Uri `
      "http://metadata.google.internal/computeMetadata/v1/project/attributes/sshKeys"
  } catch {}
  $response= $r1 + $r2

  # Split the response into lines; handle both \r\n and \n line breaks.
  $tuples = $response -split "\r?\n"

  $usersToKeys = @{}
  foreach($line in $tuples) {
    if ([string]::IsNullOrEmpty($line)) {
      continue
    }
    # The final parameter to -Split is the max number of strings to return, so
    # this only splits on the first colon.
    $username, $key = $line -Split ":",2
    if (!$usersToKeys.ContainsKey($username)) {
      $usersToKeys[$username] = @($key)
    } else {
      $keyList = $usersToKeys[$username]
      $usersToKeys[$username] = $keyList + $key
    }
  }
  $usersToKeys.GetEnumerator() | ForEach-Object {
    $username = $_.key

    # We want to create an authorized_keys file in the user profile directory
    # for each user, but if we create the directory before that user profile
    # has been created first by Windows, then Windows will create a different
    # user profile directory that looks like "<user>.KUBERNETES-MINI" and sshd
    # will look for the authorized_keys file in THAT directory. In other words,
    # we need to create the user first before we can put the authorized_keys
    # file in that user profile directory. The user-profile.psm1 module (NOT
    # FOR PRODUCTION USE!) has Create-NewProfile which achieves this.
    #
    # Run "Get-Command -Module Microsoft.PowerShell.LocalAccounts" to see the
    # build-in commands for users and groups. For some reason the New-LocalUser
    # command does not create the user profile directory, so we use the
    # auxiliary user-profile.psm1 instead.

    $pw = [System.Web.Security.Membership]::GeneratePassword(16,2)
    try {
      # Create-NewProfile will throw this when the user profile already exists:
      #   Create-NewProfile : Exception calling "SetInfo" with "0" argument(s):
      #   "The account already exists."
      # Just catch it and ignore it.
      Create-NewProfile $username $pw -ErrorAction Stop

      # Add the user to the Administrators group, otherwise we will not have
      # privilege when we ssh.
      Add-LocalGroupMember -Group Administrators -Member $username
    } catch {}

    $userDir = -join("C:\Users\", $username)
    If (!(Test-Path $userDir)) {
      # If for some reason Create-NewProfile failed to create the user profile
      # directory just continue on to the next user.
      continue
    }

    $keysFile = -join($userDir, "\.ssh\authorized_keys")
    New-Item -ItemType file -Force $keysFile
    ForEach ($sshKey in $_.value) {
      # authorized_keys and other ssh config files must be UTF-8 encoded:
      # https://github.com/PowerShell/Win32-OpenSSH/issues/862
      # https://github.com/PowerShell/Win32-OpenSSH/wiki/Various-Considerations
      Add-Content -Encoding UTF8 $keysFile $sshKey
    }
  }
  Start-Sleep -sec $pollInterval
}'
  Log "${writeSshKeys}:`n$(Get-Content -Raw ${writeSshKeys})"

  $writeKeysProcess = Start-Process `
    -FilePath "powershell.exe" `
    -ArgumentList @("-Command", ${writeSshKeys}) `
    -WindowStyle Hidden -PassThru `
    -RedirectStandardOutput "NUL" `
    -RedirectStandardError C:\write-ssh-keys.err
  Log "$(${writeKeysProcess} | Out-String)"
}

Export-ModuleMember -Function InstallAndStart-OpenSSH
Export-ModuleMember -Function StartProcess-WriteSshKeys
