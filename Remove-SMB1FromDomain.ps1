<#
.NOTES
WannaPryOffSMB1
Version 1.0 (May 15, 2017)
(c) 2017 Colin Cogle <colincogle@startmail.com>.  All Rights Reserved.

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public
License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public License for more
details.

You should have received a copy of the GNU Affero General Public License along with this program.  If not, see
<http://www.gnu.org/licenses/>.

.SYNOPSIS
Disables and removes SMB 1.0/CIFS support from an entire domain.

.DESCRIPTION
This script attempts to connect to every computer in the current Active Directory domain, and once connected, it
disables SMB1, and if possible, removes the SMB 1.0/CIFS File Sharing Support by any supported means necessary:

 - On Windows 8 and newer, and Windows Server 2012 and newer, SMB1 is disabled immediately.
 
 - On Windows 8.1 and newer, and Windows Server 2012 R2 and newer, the SMB 1.0/CIFS File Sharing Support feature is
   marked for removal.  It will be removed at the next reboot.
   
 - Windows Vista, Windows 7, and the Server 2008 family do not have a native method of disabling or removing SMB1,
   so we use Microsoft-sanctioned registry edits.  For more information, see http://aka.ms/disablesmb1.  A reboot
   will be required for the change to take effect.
 
If a computer is running Windows XP, Windows Server 2003, or Windows 8.0, the user will be notified to patch those
systems by hand.  A future release may add support for automated patching where possible.

.PARAMETER RemoteCredential
If the local user does not have permission to log onto remote computers and perform administrative tasks,
provide alternate credentials.

.PARAMETER Restart
If specified, the remote computers will be immediately rebooted to apply feature or registry changes.

.EXAMPLE
Remove-SMB1FromDomain

Connects (as the current user) to all computers in the domain to disable/remove SMB1.  Remote computers are NOT
automatically rebooted.

.EXAMPLE
Remove-SMB1FromDomain -RemoteCredential (Get-Credential CONTOSO\LocalAdmin) -Restart

Connects (as the CONTOSO\LocalAdmin user account) to all computers in the domain to disable/remove SMB1, and
restarts them immediately afterwards (if required).

.NOTES
The Active Directory PowerShell module must be installed on the computer running the script.

Special thanks to the WannaCrypt team for making my life annoying, and to Microsoft for leaving SMB1 enabled for a
decade after it was obsoleted.

.LINK
Set-SMBServerConfiguration
Uninstall-WindowsFeature
Disable-WindowsOptionalFeature
https://github.com/rhymeswithmogul/wannapry-smb1/
http://aka.ms/disablesmb1


#>

#Requires -Module ActiveDirectory
[CmdletBinding()]
Param(
	[switch]
	$Restart = $false,
	
	[System.Management.Automation.PSCredential]
	$RemoteCredential = [System.Management.Automation.PSCredential]::Empty
)

Set-StrictMode -Version Latest

Import-Module ActiveDirectory -Cmdlet Get-ADComputer -ErrorAction Stop

Get-ADComputer -Filter * -Property OperatingSystem | ForEach-Object {
	Write-Verbose "Computer name: $($_.Name)."
	Write-Debug   "> Computer is running $($_.OperatingSystem)"
	
	################################################
	### Windows 8.1 and Windows 10:
	### 1. Immediately disable SMB1 via PowerShell.
	### 2. Queue the feature for removal.
	#################################################
	If ($_.OperatingSystem -Match "Windows 10" -or $_.OperatingSystem -Match "Windows 8.1") {
		Write-Debug "> Operating system is Windows 8.1 or 10."
		Write-Debug "> Connecting to the remote computer..."
		Invoke-Command -Credential $RemoteCredential -ComputerName $_.Name -ScriptBlock {
			Write-Debug ">> Checking to see if SMB1 is enabled."
			If ((Get-SMBServerConfiguration).EnableSMB1Protocol -eq $true) {
				Write-Debug  ">>> SMB1 is enabled; disabling."
				Write-Output "Disabling SMB1 on $($env:computername)"
				Set-SMBServerConfiguration -EnableSMB1Protocol:$false -Confirm:$false
			} Else {
				Write-Debug ">>> SMB1 was not enabled."
			}
			
			Write-Debug ">> Checking to see if SMB1 is installed."
			If ((Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol").State -eq "Enabled") {
				Write-Debug  ">>> SMB1 is installed; removing."
				Write-Output "Removing SMB1 from $($env:computername)"
				If ($Restart -eq $true) {
					Write-Debug ">>>> Removing the SMB1 feature and restarting."
					Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol"
				} Else {
					Write-Debug ">>>> Removing the SMB1 feature."
					Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart
					Write-Debug ">>>> Due to user request, the remote computer will not be rebooted automatically."
					Write-Warning "A restart is required to remove SMB1 from $($env:computername)."
				}
			}
		}
	}
	
	################################################
	### Windows Server 2012 R2 and 2016
	### 1. Immediately disable SMB1 via PowerShell.
	### 2. Queue the feature for removal.
	#################################################
	ElseIf ($_.OperatingSystem -Match "Windows Server 2016" -or $_.OperatingSystem -Match "Windows Server 2012 R2") {
		Write-Debug "> Operating system is Windows Server 2012 R2 or 2016."
		Write-Debug "> Connecting to the remote computer..."
		Invoke-Command -Credential $RemoteCredential -ComputerName $_.Name -ScriptBlock {
			Write-Debug ">> Checking to see if SMB1 is enabled."
			If ((Get-SMBServerConfiguration).EnableSMB1Protocol -eq $true) {
				Write-Debug  ">>> SMB1 is enabled; disabling."
				Write-Output "Disabling SMB1 on $($env:computername)"
				Set-SMBServerConfiguration -EnableSMB1Protocol:$false -Confirm:$false
			} Else {
				Write-Debug ">>> SMB1 was not enabled."
			}
			
			Write-Debug ">> Checking to see if SMB1 is installed."
			If ((Get-WindowsFeature -Name FS-SMB1).InstallState -eq "Installed") {
				Write-Debug  ">>> SMB1 is installed; removing."
				Write-Output "Removing SMB1 from $($env:computername)"
				If ($Restart -eq $true) {
					Write-Debug ">>>> Removing the SMB1 feature and restarting."
					Uninstall-WindowsFeature -Name FS-SMB1 -Restart
				} Else {
					Write-Debug ">>>> Removing the SMB1 feature."
					Uninstall-WindowsFeature -Name FS-SMB1
					Write-Debug ">>>> Due to user request, the remote computer will not be rebooted automatically."
					Write-Warning "A restart is required to remove SMB1 from $($env:computername)."
				}
			}
		}
	}
	
	#######################################################
	### Windows Server 2012 RTM:
	### Immediately disable SMB1 via PowerShell.
	###
	### Windows 8.0:
	### 1. Immediately disable SMB1 via PowerShell.
	### 2. Warn the user that they need to upgrade or patch!
	########################################################
	ElseIf ($_.OperatingSystem -Match "Windows Server 2012" -or $_.OperatingSystem -Match "Windows 8") {
		Write-Debug "> Operating system is Windows 8.0 or Windows Server 2012 RTM."
		Write-Debug "> Connecting to the remote computer..."
		Invoke-Command -Credential $RemoteCredential -ComputerName $_.Name -ScriptBlock {
			Write-Debug ">> Checking to see if SMB1 is enabled."
			If ((Get-SMBServerConfiguration).EnableSMB1Protocol -eq $true) {
				Write-Debug  ">>> SMB1 is enabled; disabling."
				Write-Output "Disabling SMB1 on $($env:computername)"
				Set-SMBServerConfiguration -EnableSMB1Protocol:$false -Confirm:$false
			} Else {
				Write-Debug ">>> SMB1 was not enabled."
			}
		}
		
		If ($_.OperatingSystem -Match "Windows 8") {
			Write-Warning "$($env:computername) was patched; however, it is running Windows 8.0.  Please upgrade to Windows 8.1 from the Store, or install the patch from https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/"
		}
	}
	
	##############################################################
	### Windows Vista, 7, and Server 2008
	### Make a registry change to disable SMB1, pending reboot.
	##############################################################
	ElseIf ($_.OperatingSystem -Match "Windows Server 2008" -or $_.OperatingSystem -Match "Windows 7" -or $_.OperatingSystem -Match "Windows Vista") {
		Write-Debug "> Operating system is Windows 8.0 or Windows Server 2012 RTM."
		Write-Debug "> Connecting to the remote computer..."
		Invoke-Command -Credential $RemoteCredential -ComputerName $_.Name -ScriptBlock {
			Write-Debug ">> Checking to see if SMB1 is enabled."
			If ((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1).SMB1 -ne 0) {
				Write-Output "Disabling SMB1 on $($_.Name)"
				Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Type DWORD -Value 0 -Force
				If ($Restart -eq $true) {
					Write-Debug ">> Restarting the remote computer"
					Restart-Computer -Credential $RemoteCredential -Force
				} Else {
					Write-Debug ">>> Due to user request, the remote computer will not be rebooted automatically."
					Write-Warning "A restart is required to disable SMB1 on $($env:computername)."
				}
			}
		}
	}

	##################################################
	### Windows XP and Windows Server 2003:
	### Warn the user that there is a patch available.
	##################################################
	ElseIf ($_.OperatingSystem -Match "Windows XP" -or $_.OperatingSystem -Match "Windows Server 2003") {
		Write-Warning "$($env:computername) is running an unsupported version of Windows.  Install the appropriate patch from https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/"
	}
	
	###
	### For everything else, warn the user.
	###
	Else {
		Write-Warning "The computer $($env:computername) is running an unsupported operating system."
	}
}
