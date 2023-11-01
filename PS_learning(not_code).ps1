Powershell MasterClass John Savill's - Part 2

Remote Management with PowerShell

RPC, no thank you!
Traditionally Remote Procedure Call (RPC) was used for a remote interaction
This uses many ports and configuring a firewall was a hard task to do.
Normally firewall was disabled
Microsoft moves away from RPC

Introducing WinRM
WS-Man is a standard protocol for remote management using HTTP and HTTPS and WinRM is the Windows implementation
It doesn't use a port 80 or 443 so does not conflict (it did with a WinRM 1.1 and earlier)
WinRM uses a HTTP port 5985, HTTP uses 5986 (when used).
In prodcution HTTPS should used so content is encrypted  (or use a IPSEC)

Enabling a WinRM
WinRM is installed by default on WIndows 2008R2 and above (which had PowerShell v2)
WinRM is enabled by default on Windows 2012 which uses WinRM for basically everything management
WinRM must be enabled on client operating systems and other server operating systems in elevated PowerShell:
- EnablePSRemoting
- Use Group Policy

Get-PSSessionConfiguration
Enable-PSRemoting
Get-PSSessionConfiguration

Invoke-Command

Can be one-to-many
Can invoke commands to an existing session
When used with a cmputer session is created then terminated meaning state state is not persisted
Data is serialized into XML when sent back then deserialized back to objects in local session
These objects are not linked to the original anymore so perform all actions on the remote as needed and optimize what is returned as serialization/deserialization is computatonally expensive


#enabling WinRM and PS Remoting
Enable-PSRemoting

Invoke-Command -ComputerName savazuusscdc01 {$env:computername}
Invoke-Command -ComputerName savazuusscds01 {$var=10}
Invoke-Command -ComputerName savazuusscds01 {$var}

#Filter on remote and perform actions or strange results
Invoke-Command -ComputerName savazuusscdc01 -ScriptBlock {get-eventlog -logname security} | select-object -First 10
Invoke-command -computername savazuusscdc01 -scriptblock {get-eventlog -logname security | select-object -first 10}
Invoke-command -computername savazuusscdc01 -scriptblock {get-eventlog -logname security -newest 10}

Invoke-Command -ComputerName savazuusscdc01 -ScriptBlock {get-process} | where {$_.name -eq "notepad"} | Stop-Process
Invoke-Command -ComputerName savazuusscdc01 -ScriptBlock {get-process | where {$_.name -eq "notepad"} | Stop-Process }

Measure-Command {Invoke-Command -ComputerName savazuusscdc01 -ScriptBlock {get-process} | where {$_.name -eq "notepad"} }
Measure-Command {Invoke-Command -ComputerName savazuusscdc01 -ScriptBlock {get-process | where {$_.name -eq "notepad"}} }

PS C:\WINDOWS\system32> measure-command {Invoke-Command -ComputerName serwerzzo -ScriptBlock {get-process} | where {$_.name -eq "notepad"}}


Days              : 0
Hours             : 0
Minutes           : 0
Seconds           : 8
Milliseconds      : 306
Ticks             : 83067583
TotalDays         : 9,61430358796296E-05
TotalHours        : 0,00230743286111111
TotalMinutes      : 0,138445971666667
TotalSeconds      : 8,3067583
TotalMilliseconds : 8306,7583



PS C:\WINDOWS\system32> measure-command {Invoke-Command -ComputerName serwerzzo -ScriptBlock {{get-process} | where {$_.name -eq "notepad"}}}


Days              : 0
Hours             : 0
Minutes           : 0
Seconds           : 0
Milliseconds      : 665
Ticks             : 6656149
TotalDays         : 7,70387615740741E-06
TotalHours        : 0,000184893027777778
TotalMinutes      : 0,0110935816666667
TotalSeconds      : 0,6656149
TotalMilliseconds : 665,6149

_______

By default only 32 concurrent connections. Can be changed with - ThrotleLimit <new number>

#Sessions
$session = New-PSSession -ComputerName savazuusscds01
Invoke-Command -SessionName $session {$var=10}
Invoke-Command -SessionName $session {$var}
Enter-PSSession -Session $session  #also interactive
Get-PSSession
$session | Remove-PSSession

#Multiple machines
$dcs = "savazuusedc01", "savazuusscdc01"
Invoke-Command -ComputerName $dcs -ScriptBlock {$env:computername}
$sess = New-PSSession -ComputerName $dcs
$sess
icm –session $sess –scriptblock {$env:computername}
enter-pssession -session $dcs[0]
$sess | remove-pssession

Session and Enter-PSSession

One-to-one
Can create a sessions in advance then enter the session or just create on demand
Can import-modules FROM a session and then execute them , known as implicit remoting

#Implicit remoting
$adsess = New-PSSession -ComputerName savazuusscdc01
Import-Module -Name ActiveDirectory -PSSession $adsess
Get-Module #type different from the type on the actual DC
Get-Command -Module ActiveDirectory #functions instead of cmdlets
Get-ADUser -Filter *
$c = Get-Command Get-ADUser
$c.Definition
Remove-Module ActiveDirectory
Import-Module -Name ActiveDirectory -PSSession $adsess -Prefix OnDC
Get-Command -Module ActiveDirectory
Get-OnDCADUser -Filter *  #I don't have regular Get-ADUser anymore

$comm = "get-process"
$comm
&$comm

Can add a prefix so can load module on multiple remote sessions

Compability with PowerShell Core

Powershell continues to have more cmdlets available however there are still some only available for Windows Powershell
The Windows Powershell Compability module works in a similar way to implicit
Modules are loaded by creating a session to the local machine then creating function definitions that redirect to the local session that uses Windows PowerShell

#Execution operator &
$comm = "get-process"
$comm   #Nope
&$comm  #Yep!

#PowerShell Core Compatibility with Windows PowerShell modules
get-module -ListAvailable -SkipEditionCheck
Get-EventLog  #Fails in PowerShell Core
Install-Module WindowsCompatibility -Scope CurrentUser
Import-WinModule Microsoft.PowerShell.Management
Get-EventLog -Newest 5 -LogName "security"
#Behind the scenes
$c = Get-Command get-eventlog
$c
$c.definition
Get-PSSession #Note the WinCompat session to local machine

Alternate Endpoints

Get-PSSessionConfiguration shows available endpoints 
JEA leverages this heavily for constrained endpoints which contain subsets of privileges and cmdlets

#Alternate endpoint
Enable-WSManCredSSP -Role "Server" -Force
New-PSSessionConfigurationFile –ModulesToImport OneTech, ActiveDirectory, Microsoft.PowerShell.Utility `
	–VisibleCmdLets ('*OneTech*','*AD*','format*','get-help') `
	-VisibleFunctions ('TabExpansion2') -VisibleAliases ('exit','ft','fl') –LanguageMode ConstrainedLanguage `
	-VisibleProviders FileSystem `
	–SessionType ‘RestrictedRemoteServer’ –Path ‘c:\dcmonly.pssc’
Register-PSSessionConfiguration -Name "DCMs" -Path C:\dcmonly.pssc -StartupScript C:\PSData\DCMProd.ps1

$pssc = Get-PSSessionConfiguration -Name "DCMs"
$psscSd = New-Object System.Security.AccessControl.CommonSecurityDescriptor($false, $false, $pssc.SecurityDescriptorSddl)

$Principal = "savilltech\DCMs"
$account = New-Object System.Security.Principal.NTAccount($Principal)
$accessType = "Allow"
$accessMask = 268435456
$inheritanceFlags = "None"
$propagationFlags = "None"
$psscSd.DiscretionaryAcl.AddAccess($accessType,$account.Translate([System.Security.Principal.SecurityIdentifier]),$accessMask,$inheritanceFlags,$propagationFlags)
Set-PSSessionConfiguration -Name "DCMs" -SecurityDescriptorSddl $psscSd.GetSddlForm("All") -Force
#Set-PSSessionConfiguration -Name "DCMs" -ShowSecurityDescriptorUI
Restart-Service WinRM

Robust Connection

If a session is disconnected Powershell will try on its own for up to 4 minutes to re-establish the connection
Can disconnect from sessions then reconnect and the state is maintained 

Authentication

The account you use to run commands is used on remote machine even though WinRM runs as local system (which it always should)
Your credential can be used on the remote machine but cannot be hopped to another machine from that machine
If hopping is required then CredSSP can be used 
Once enabled you must use -Authentication CredSSP -Credential <credential> when using Cred SSP
Kerberos delegation is another option that will work if machines are in trusted domain/forest
Also certificate authentication may be an option when using SSL

cd wsman:
cd .\localhost\Client\Auth
ls
   WSManConfig: Microsoft.WSMan.Management\WSMan::localhost\Client\Auth

Type            Name                           SourceOfValue   Value
----            ----                           -------------   -----
System.String   Basic                                          true
System.String   Digest                                         true
System.String   Kerberos                                       true
System.String   Negotiate                                      true
System.String   Certificate                                    true
System.String   CredSSP                                        false

Connection Outside Trusted Domains

Mutual authentication works within domains or trusted domains with no extra work
For connecions to other machines outside trusted domains, not in domain or not using the machines AD name (eg. DNS alias, IP Address) mutual authentication is not possible without an extra work 
For above scenarios either:
- Enable HTTPS connections using CA issued SSL certificates on the remote machine 
- add name /IP to the WinRM TrustedHosts list

Trusted Host

cd wsman:
cd .\localhost\Client
ls 
set-item -path .\TrustedHosts -Value ' '
ls
set-item -path .\TrustedHosts -Value '<adres_IP>'
set-item -path .\TrustedHosts -Value '<dns_name>'
set-item -path .\TrustedHosts -Value '*' #verybad
set-item -path .\TrustedHosts -Value ' '

Troubleshooting

try with a telnet to node <ip> port 5985
Application and Service logs -> Microsoft -> Windows -> PowerShell -> Operational and will see information about connections 
Windows Remote Management -> Operational would see problems about connections if there were issues 

Import-Module PSDiagnostics
Get-command -module PSDiagnostics
Enable-pswsmancombinedtrace 
Invoke-command -ComputerName comp1 -ScriptBlock {get-process}
Disable-PSWSManCombinedTrace

HTTPS and SSL

Uses a certificate to confirm the indentity of the target server 
A seperate SSL encrypted connection and port that must be enabled 
Avoid using makecert for the certificate (as this defeats many of the benefits)
Use a cert from internal trusted CA or external CA
Name in certificate must match the name you will connect to the server as 

#Enabling HTTPS
Winrm create winrm/config/Listener?Address=*+Transport=HTTPS @{Hostname="host";CertificateThumbprint="thumbprint"}
#e.g.
cd Cert:\LocalMachine\My
Get-ChildItem #or ls remember. Find the thumbprint you want
winrm create winrm/config/listener?address=*+Transport=HTTPS @{Hostname="savazuusscdc01.savilltech.net";CertificateThumbprint="B4B3FAE3F30944617E477F77756D6ABCB9980E38"}
New-NetFirewallRule -DisplayName "Windows Remote Management (HTTPS-In)" -Name "Windows Remote Management (HTTPS-In)" -Profile Any -LocalPort 5986 -Protocol TCP

Connecting using SSL 

Add -UseSSL (and credential when outside of domain or just want to!)
-SkipCACheck - Don't worry if SSL is from a trusted CA (would need this if used makecert for example)
-SkipCNCheck - Don't worry if the certificate does not match the name you are connecting two
Outside of lab both of this options are good ways to get in trouble as they defeat mutual authentication 
$cred=get-credential
Enter-PSSession <domain_name> -Credential $cred -UseSSL

#To view - must be elevated
winrm enumerate winrm/config/Listener

#Connect using SSL
Invoke-Command savazuusscdc01.savilltech.net -ScriptBlock {$env:computername} -UseSSL
#Short name will fail as using cert can override
$option = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
Enter-PSSession -ComputerName savazuusscdc01 -SessionOption $option -useSSL

https://www.hollywoodreporter.com/lists/best-tv-shows-21st-century/chernobyl-hbo-2019/

A Quick Word about Non-WIndows and Linux SSH

Powershell embraces cross-platform 
As does Visual Studio Code enabling complete, consistent expierience 
While WinRM is commonly used it is also possible to use SSH (for both Linux and Windows)
For Windows need OpenSSH installed (part of 1809+) and for Linux/MacOS use the apprproprieate SSH remoting feature

invoke-command -hostname <ip_address> -UserName john -ScriptBlock {get-host}

#Connection via SSH  hostname instead of computername
Invoke-Command -HostName savazuussclnx01 -ScriptBlock {get-process} -UserName john

#Mix of WinRM and SSH
New-PSSession -ComputerName savazuusscds01  #winrm
New-PSSession -HostName savazuussclnx01 -UserName john
Get-PSSession -OutVariable sess
$sess
invoke-command $sess {get-process *s}
$sess | Remove-PSSession

Module 4 - PowerShell Scripting

Signed Scripts

Get-ExecutionPolicy
By default the environment is restricted
Set-ExecutionPolicy used to change to
- RemoteSigned (trusted publisher for external scripts)
- AllSigned (trusted publisher for any script including your own)
- Unrestricted (run anything and not recommended!!)
- Also is bypass which doesn’t care about it
For our testing RemoteSigned is good -> default after WS2012

#Shows write-host vs write-output
function Receive-Output
{
    process { write-host $_ -ForegroundColor Green}
}
Write-Output "this is a test" | Receive-Output -> stanie się zielone
Write-Host "this is a test" | Receive-Output -> to nie stanie się zielone, bo jest “Host”
Write-Output "this is a test"

Execute Script

From Powershell -> ./script.ps1
From cmd.exe -> Powershell [-noexit] “& <path>\<script>.ps1 
ALBO push -command “&.\addnumbers.ps1”

Write-Host vs Write-Output

Remember the various Out targets and the pipeline
These two cmdlets are not equal but initially appear to have the same result
The goal of PowerShell is to support data to pass along the Powershell Objectflow engine
Write-Host outputs data directly to the host and not along the pipeline
Write-Output has its output continue down the pipeline
Always use Write-Output as Write-Host limits the handling of data

Why have Write-Host

Because it can do pretty output formatting now possible with Write-Output

Write-Host “You are looking” -NoNewLine
Write-Host “AWESOME” -ForegroundColor Red `
-BackgroundColor Yellow -NoNewLine
Write-Host “ today”

WYNIK -> You are looking AWESOME today

Write-warning “Danger”
Write-error “danger”

#' vs "
The difference is minimal
Generally use single quotes
Variables in double quotes are replaced with their values but not in single quotes
Double quotes enable delimiting within a string
Can use a escape characters in double quotes

$name = "John"
Write-Output "Hello $name"
Write-Output 'Hello $name'
$query = "SELECT * FROM OS WHERE Name LIKE '%SERVER%'"
Write-Output "Hello `t`t`t World"

Prompting the user

Read-Host is an easy way to get input
Possible to add -AsSecureString to avoid displaying to screen and storing securely

$name = Read-Host “Who are you?”
$pass = Read-Host “What’s is your password?” -AsSecureString [Runtime.InteropServices.Marsal]::PtrToStringAuto([Runtime.interopServices.Marshal]::SecureStringToBSTR($pass)) -> pokazuje dokładnie w plaintexcie wpisane hasło :D

#User input
$name = Read-Host "Who are you?"
$pass = Read-Host "What's your password?" -AsSecureString
[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pass)) -> co wyzej :D

First Script

Param(
[string]$computername='savazuusscdc01')
Get-WmiObject -class win32_computersystem `
	-ComputerName $computername |
	fl numberofprocessors,totalphysicalmemory

Get-WMIObject is not available in Powershell Core

.\Mod4Script1.ps1 <name_of_machine>
Przekazanie parametru do scriptu, alternatywnie zamiast domyślnego :D

#CIM EDITION
Param(
[string]$computername='savazuusscdc01')
Get-CimInstance -ClassName win32_computersystem `
	-ComputerName $computername |
	fl numberofprocessors,totalphysicalmemory

Script with mandatory input

Param(
[Parameter(Mandatory=$true)][string[]]$computers) # deklaracja zmiennych
foreach ($computername in $computers) # pętla po zadeklarowanych komputerach
{
    $win32CSOut = Get-CimInstance -ClassName win32_computersystem -ComputerName $computername # przywołanie do zmiennej 
    $win32OSOut = Get-CimInstance -ClassName win32_operatingsystem -ComputerName $computername

    $paramout = @{'ComputerName'=$computername; #hash table about different parameters
    'Memory'=$win32CSOut.totalphysicalmemory;
    'Free Memory'=$win32OSOut.freephysicalmemory;
    'Procs'=$win32CSOut.numberofprocessors;
    'Version'=$win32OSOut.version}

    $outobj = New-Object -TypeName PSObject -Property $paramout # creating an object
    Write-Output $outobj
}

MOZESZ TEN SKRYPT inaczej wyświetlić
.\script.ps1 <parameter1> <parameter2> | ft

Get-CimInstance -ClassName Win32_Logical  #ctrl space to intelli sense all the name spaces available


TRY-CATCH Module 4.2

function Get-RandomMessageSad
{
    $number=Get-Random -Maximum 10

    switch ($number)
    {
        {$_ -lt 4} { write-output "Howdy Y'all"}
        {$_ -ge 4 -and $_ -lt 7} { write-output "Good morning to thee"}
        Default { write-output "Top of the morning"}
    }
}

function Get-RandomMessage
{
    #Need cmdlet binding for the standard verbose, debug etc options
    [CmdletBinding()]
    Param([parameter(ValueFromRemainingArguments=$true)][String[]] $args)

    Write-Verbose "Generating a random number"
    $number=Get-Random -Maximum 10
    Write-Verbose "Number is $number"

    Write-Debug "Start of switch statement"
    switch ($number)
    {
        {$_ -lt 4} { write-output "Howdy Y'all"; Write-Debug "Less than 4" }
        {$_ -ge 4 -and $_ -lt 7} { write-output "Good morning to thee"; Write-Debug "4-6"}
        Default { write-output "Top of the morning"; Write-Debug "Default"}
    }
}

#Docs are great! https://docs.microsoft.com/en-us/powershell/scripting/learn/deep-dives/everything-about-exceptions?view=powershell-7.1

#Region Regular Error
#Lets make an error
Get-Content -Path r:\doesnotexist\nothere.txt
Throw("Johns Error") #Can always just throw my own!
#Look at the last error
Get-Error
#Also default error variable that errors added to
$Error
#Endregion

#Region Custom variable
#Can error to my own variable
Get-Content -Path r:\doesnotexist\nothere.txt -ErrorVariable BadThings #Note if did +BadThings would add content to existing
$BadThings
#Could do a check
if($BadThings)
{
    Write-Host -ForegroundColor Blue -BackgroundColor White "Had an issue, $($BadThings.Exception.Message)"
}
#Endregion

#Region Using Try-Catch
#Handle the error with try-catch
try {
    Get-Content -Path r:\doesnotexist\nothere.txt
}
catch {
    Write-Output "Something went wrong"
}

#Didn't work, why?
#Endregion

#Region Try-Catch terminating
#We have to set an error action for the try-catch to work since the get-content by default is not a terminating error
#Try-catch only catches terminating errors, e.g
try {
    asdf-asdfasd #garbage and is terminating
}
catch {
    write-output "No idea what that was"
}
#Endregion

#Region Make terminating with ErrorAction
#Make our normal non-terminating error a terminating with the error action
try {
    Get-Content -Path r:\doesnotexist\nothere.txt -ErrorAction Stop
}
catch {
    Write-Output "Something went wrong"
}
#Endregion

#Region Types of error action
#Note there are other types of ErrorAction
Get-Content -Path r:\doesnotexist\nothere42.txt -ErrorAction SilentlyContinue
Get-Error #still errored, we just didn't see it!
#Endregion

#Region Looking at details
#Can look at the error details
try {
    Get-Content -Path r:\doesnotexist\nothere.txt -ErrorAction Stop
}
catch {
    $ErrorMessage = $_.Exception.Message
    Write-Output "Something went wrong - $ErrorMessage"
    write-host -ForegroundColor Blue -BackgroundColor White $_.Exception #Entire exception
    #Information about where exception was thrown
    $PSItem.InvocationInfo | Format-List * #can also use $PSItem instead of $_
}
#Endregion

#Region Types of catch
#Catch can be used with specific types of exception but needs to be terminating type
try {
    asdf-asdfasd #garbage and is terminating
}
catch [System.Management.Automation.CommandNotFoundException] {
    write-output "no idea what this command is"
}
catch {
    $_.Exception
}
#Endregion

#Region Using ErrorActionPreference
#There is a default error action that is overriden by the -ErrorAction
$ErrorActionPreference

#This can be useful when we cannot set ErrorAction, e.g. a non-PowerShell call
try {
    $CurrentErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Stop"
    Get-Content -Path r:\doesnotexist\nothere.txt #any command here, e.g. cmd /c
}
catch {
    Write-Output "Something went wrong"
    write-host -ForegroundColor Blue -BackgroundColor White $_.Exception.Message
}
Finally {
    $ErrorActionPreference = $CurrentErrorActionPreference
}

#Note we used finally to put the value back to what it was before we changed it
#Finally always runs if catch is called or not
#Endregion

#Region Errors from cmd.exe
#For cmd execution it writes to its own error stream we can capture
$executionoutput = Invoke-Expression "cmd.exe /c dir r:\nofolder\nofile.file"
$executionoutput #Nope

#Need STDERR (2) to go to STDOUT (1)
$executionoutput = Invoke-Expression "cmd.exe /c dir r:\nofolder\nofile.file 2>&1"
$executionoutput
#Endregion
