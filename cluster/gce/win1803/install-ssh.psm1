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
# After installation, get a password for the 'kubernetes' user on the Windows
# VM with:
#   gcloud compute -q --project <project> reset-windows-password \
#     --user kubernetes <instance> --zone <zone> \
#     --format="value(password)" 2> /tmp/stderr.out
# Then ssh to the Windows VM:
#   ssh kubernetes@IPaddress \
#     -o PreferredAuthentications=keyboard-interactive,password \
#     -o PubkeyAuthentication=no -t "powershell -File -"
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
  (Get-Content $sshd_config_default).replace('#PasswordAuthentication yes', 'PasswordAuthentication no') `
  | Set-Content $sshd_config

  # Configure the firewall to allow inbound SSH connections
  New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22

  # Start the services and configure them to automatically start on subsequent
  # boots:
  ForEach ($service in ("sshd", "ssh-agent")) {
    net start ${service}
    Set-Service ${service} -StartupType Automatic
  }
}

# Start a job to retreive ssh keys from the metadata server and write them to
# user-specific directories.
# This is intended to use only for tests.
function StartJob-WriteSSHKeys{
  Start-Job -Name Write-Keys -ScriptBlock {
    # TODO: log and report errors.
    while($true) {
      $response = Invoke-RestMethod -Headers @{"Metadata-Flavor"="Google"} -Uri "http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys"
      # Split the response into lines; handle both '\r\n' and '\n' line breaks.
      $tuples = $response -split '\r?\n'
      foreach($line in $tuples) {
        $data = $line -Split ":"
        $username, $key = $data[0], $data[1]

        $target_dir = "C:\Users\$username\.ssh"
        If(!(test-path $target_dir)) {
          # Create the user directory if it doesn't exist.
          New-Item -ItemType Directory -Force -Path $target_dir
        }
        # Always override the keys; this does NOT handle multiple keys for the
        # same user.
        $target_path = "$target_dir\authorized_keys"
        Set-Content $target_path $key
      }

      Start-Sleep -sec 60
    }
  }
}


Export-ModuleMember -Function InstallAndStart-OpenSSH
Export-ModuleMember -Function StartJob-WriteSSHKeys
