# Install open-ssh using the instructions in
# https://github.com/PowerShell/Win32-OpenSSH/wiki/Install-Win32-OpenSSH
function Install-OpenSSH{
  # Download open-ssh.
  $url = "https://github.com/PowerShell/Win32-OpenSSH/releases/download/v7.7.2.0p1-Beta/OpenSSH-Win32.zip"
  $ProgressPreference = 'SilentlyContinue'
  Invoke-WebRequest $url -OutFile C:\openssh-win32.zip

  # Unzip and install open-ssh
  Expand-Archive c:\openssh-win32.zip -DestinationPath "C:\Program Files\OpenSSH"
  powershell.exe -ExecutionPolicy Bypass -File "C:\Program Files\OpenSSH\OpenSSH-Win32\install-sshd.ps1"

  # Configure the firewall to allow inbound SSH connections
  New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22

  # Set up the service
  Set-Service ssh-d -StartupType Automatic
  Set-Service ssh-agent -StartupType Automatic
}

# Start a job to retreive ssh keys from the metadata server and write them to
# user-specific directories.
# This is intended to use only for tests.
function StartJob-WriteSSHKeys{
  Start-Job -Name Write-Keys -ScriptBlock {
    # TODO: log and report errors.
    while($true) {
      $response = Invoke-RestMethod -Headers @{"Metadata-Flavor"="Google"} -Uri "http://metadata.google.internal/computeMetadata/v1/project/attributes/sshKeys"
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


Export-ModuleMember -Function Install-OpenSSH
Export-ModuleMember -Function StartJob-WriteSSHKeys
