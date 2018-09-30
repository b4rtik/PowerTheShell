# PowerTheShell

This repository was created for teaching / demonstration purposes and is based on a post by <a href="https://twitter.com/_xpn_" rel="nofollow">@<em>xpn</em></a>, more details available <a href="https://www.mdsec.co.uk/2018/06/exploring-powershell-amsi-and-logging-evasion/" rel="nofollow">here</a>..

The goal is:

1. Perform everything in memory without touching the hard disk
2. Run well-known scripts without being intercepted by the AV
3. Execute payload meterpreter without being intercepted by the AV
4. Minimize tracks in EventViewer

The main script Console-Setup.ps1 performs one of the following AMSI evasion techniques:

1. Reflection by Matt Graeber (@mattifestation)
2. Patching by Tal Liberman (@Tal_Liberman)
3. Erro forcing by Adam Chester (@_xpn_)

The main script also performs the necessary commands for protecting our operational security:

1. bypass block bypass script by Adam Chester (@_xpn_)

Once the setup phase is over, you can run the console and all its scripts without using any of them
obfuscation technique. In fact, only the commands necessary for AMSI evasion technique are blurred.

This repository contains well-known scripts such as Invoke-Mimikatz Invoke-Powershell Invoke-CrerdentialPhisher that
they have been patched or customized for easy integration. The actions performed do not compromise the signature of the scripts.
