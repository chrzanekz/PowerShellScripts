Powershell Tasks

Prerequisites
* PowerShell version 5.1 / PowerShell 6+
* NuGet (Windows only)
* Pester v4.x

Although I've tried all the previous answers, only the following one worked out:
1 - Open Powershell (as Admin)
2 - Run:
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

3 - Run:
Install-PackageProvider -Name NuGet


# PS 5.1 (upgrade to latest Pester)
Install-Module Pester -Force -SkipPublisherCheck -Scope CurrentUser -MinimumVersion 5.0.2

# PS 6.0+ (Install Pester under current user)
Install-Module Pester -Scope CurrentUser -MinimumVersion 5.0.2

Powershell MasterClass John Savill's

Powershell Fundamentals

CMD before Powershell

dir - wyświetlanie wszystkich plików
ipconfig
dir /s dir.exe -> dir.exe nie istnieje jako osobna instancja
dir /s ipconfig.exe -> istnieje jako osobna instancja
dir | sort
dir /b /s | sort

WMI, VBScript, JScript

Powershell Monad codename
built on .NET Core

dir | sort-object

dir | sort-object -Descending -Property LastWriteTime

dir | foreach{ "$($_.GetType().FullName) - $_.name" }

Simpler Language and Standard Based
<verb>-<noun>
get-childitem -> dir

PowerShell can manage non-Windows such as Linux as WSMan and CIM (WMI2) are the default protocols for management
PowerShell Core utilizies SSH in addition to WSMan
Remote management enabled as a default
.Net is required for working PowerShell
PowerShell was available as part of WMF (Windows Management Framework)
GetItem-PropertyValue

OneGet -> tool for Chocolatey 
$PSVersionTable

Most exiting things works only on PowerShell Core

Cross-platform usage because of .NET Core

Get-Module -listavailable -> all of the modules PowerShell

Get-Module -listavailable -skipeditioncheck -> all of the modules PowerShell without showing compatible versions

Powershell Core is something different from a PowerShell Desktop version.
GitHub.com/powershell/powershell/

Pwsh.exe vs powershell.exe

First Script

#region Hello World
Write-Output “Hello World”

$name = “Mateusz”
Write-Output “Hello $name”
Write-Output “Hello $env:USERNAME”
#endregion

————

Choco outdated
Choco upgrade powershell-core

Chocolatey software

Get-Host 
$PSVersionTable
$PSVersiobTable.psversion

Information about a version

[intptr]::size 
If its 8 then it means that it is 64-bit version of that

Easy Access To Powershell

Admin Properties
Properties of my terminal PWSH
Height need to be highest possible
Pin to the task bar

Powershell has basic autocomplete [Tab]

It needs WPF (Windows Presentation Network) Powershell ISE

Get-alias dir

get-childitem -recurse - wszystkie podfoldery 

Full command names in scripting

Get-alias

Get-process | formatlist ALBO ft


Navigating with PowerShell

Regular command will work but file system is not the only hierarchical storage system
- Registry
- Certificate store
- Active Directory
- RDS
- IIS
These can also  be navigated and configured like a file system
Get-PSDrive
Widzimy wszystkie dane pliki, gdzie możemy przejść, właśnie rejestr albo jakieś inne ENV albo certyfikaty, AD

Tab Support

Powershell modules

Modules are loaded which contain PowerShell functionalities sich as cmdlets
Get-module
Get-module -listavailable
Import-module <module>
Get-Command -Module <module>

Get-command -Module Hyper-V | Select -Unique Noun | Sort Noun
Get-command -Module PSReadLine | Select -Unique Noun

Get-command -Module PSReadLine | Select -Unique Name | sort Name

Module Versions and Updating

Modules go through updates
Check version with 
- (Get-module <module_name>).Version
- Install-Module Az
- Update-module az

Getting Help

Get-Help <cmdlet>
Also available:
- -full
- -detailed
- -examples
- -online
- -showwindow

Get-help get-command -examples

Update-help

Get-command -noun process

Updatable Help

Help for cmdlets is pulled from the internet and installed into correct location for module (language specific)
- Update-help (run elevated)
- Save-help (save to folder and use this with above Update-Help cmdlet)
Get-Help will automatically pull down latest help
Get-Help <cmdlet> -Online for web based help information
- Get-Help New-VHD -online
- (Get-command New-VHD).helpuri

New-Item -itemtype Directory -path c:/

Git clone <git url>

Connecting Commands Together

Semicolon

get-process a* ; get-service a*

Powershell does not convert output to text but rather maintains The objects

get-process a* | get-member

Get-NetAdapter -> pokazuje adaptery sieciowe

Get-Process | Where-Object {$_.Name -eq "opera"}

(Get-Process | Where-Object {$_.Name -eq "opera"}).kill() -> zabija proces
get-process -name notepad | sort-object -property id | stop-process

Normal commands can be used with the pipelining method in powershell:
ipconfig | select-string -pattern 255

Variables
$var1 = "world"
wroite-output "Hello $var1"

$procs = "get-process"
$procs[0] | gm
$procs -> first instance of process

The pipeline
Can check the type of an object
<var>.gettype()
<var>gettype().fullname

get-process | fl
get-process | Select-Object -property name, @{name='procid'; expression={$_.id}}

get-help stop-process -full

Get-Process | Where-Object {$_.Handles -gt 1000}
Get-Process | Where Handles -gt 1000
Get-Process | Where-Object {$_.Handles -gt 1000} | Sort-Object -Property Handle | ft name, handles -AutoSize

Default Pipeline Output

Different out verb cmdlets
The default is Out-Default
Directs to Out-host
Other targets are:
- Out-Printer
- Out-GridView (can combine with -passthru to some special effects)
- Out-Null -> suppress

get-process | Out-GridView
PS C:\WINDOWS\system32> get-process | Out-GridView -PassThru | Stop-Process
Fajnie przekazuje do nowego okna, żeby skillować proces

get-process w* | clip -> przekierowuje wynik do schowka

Strumień przekierowujący
get-process > procs.txt
get-alias del -> Remove-Item
get-process | out-file procs.txt -> oznacza dokładnie ten sam strumień przekierowania
Get-Content .\procs.txt -> przywrócenie, danych na ekran
cat -> get-content

tasklist > procs.txt

Export Data
Get-Process | Format-Table/Format-List
Get-Process | Export-Csv C:/pulpit/proc.csv
Get-Process | Export-clixml C:/pulpit/proc.xml

When importing back keeps a object
Import-csv C:\stuff\proc.csv | where {$_.name -eq "notepad"} | stop-process

 get-process | Export-Csv procs.csv
$procs = import-csv .\procs.csv
get-process | Export-Clixml procs.xml
$procs = Import-Clixml .\procs.xml

Deserialized process -> coming back from a xml file

Limiting Objects Returned

Can use Sort-Object

get-process | measure-object -> liczy ilość obiektów

get-process | sort -Property ws

get-process | sort -Property WS -Descending | select -first 5

get-winevent -LogName security

get-winevent -LogName security -MaxEvents 5 -Oldest

Invoke-Command -ServerName <servername> -ScriptBlock {get-winevent -logname security -maxevents 5 -oldest}

get-netadapter | where-object {$_.name -eg "Ethernet*"} | Enable-NetAdapter-> pokaż złącza ethernet

Then combine with -descending -ascending
Send to Select-Object with -first n, -last n

Get-Process | Sort-Object -Descending -Property StartTime | Select-Object -First 5
get-process | measure-object
get-process | measure-object WS -Sum

Comparing Objects
Compare-Object can be used to compare two sets of data

You can select how to compare the objects:
- -Property <Name> - finds a differences in instances of objects in the results
- Without this any changes would be displayed

PS C:\WINDOWS\system32> $procs = get-process
PS C:\WINDOWS\system32> $procs2 = get-process
PS C:\WINDOWS\system32> Compare-Object -ReferenceObject $procs -DifferenceObject $procs2

Compare-Object -ReferenceObject $procs -DifferenceObject $procs2 -Property name

Site Indicator shows us whch processes are changed and which are not

Advanced Outputs

There are various ConvertTo cmdlets for advanced outputs: 
- HTML
- JSON
- CSV
- XML
- Secure String

We can combine this with a Out-File to the formatted output to a file,

Doing things with objects

Outputting to a file is great but the real power is using a cmdlets together and keeping the objects
Cmdlets need to be able to accept as input objects output from the previous cmdlets in the pipeline

get-process | Stop-Process -whatif

Can use a -passthru with some commands to allow objects to continue a down to the pipeline 
get-aduser bruce | Disable-ADAccount -Passthru

-confirm and -whatif commands

These are parameters that can be added to other commands
Confirm asks for confirmation of doing a series of tasks
and what if is useful when it is going to a evaluate a series of tasks

EnterPSSession -computername <computername>

get-aduser -filter * -properties "LastLogOnDate" | where {$_.LastLogonDate -le (Get-Date).AddDays(-60)} | sort-obejct -property lastlogondate -descending | format-table -property name, lastlogondate

Get-LocalUser -filter * -properties "LastLogOnDate" | where {$_.LastLogonDate -le (Get-Date).AddDays(-60)} | sort-object -property lastlogondate -descending | format-table -property name, lastlogondate

get-localuser * | select -property lastlogon, name | where {$_.lastlogon -gt (Get-Date).AddDays(-180)}

DisableADAccount -whatif

More -Confirm

Every cmdlet has an impact level
If the impact level is equal or higher than the confirmation preference setting user will be prompted for confirmation
$confirmpreference

PS C:\WINDOWS\system32> $confirmpreference
High
PS C:\WINDOWS\system32> $confirmpreference = "medium"
PS C:\WINDOWS\system32> notepad
PS C:\WINDOWS\system32> get-process | where {$_.name -eq "notepad"} | stop-process

Find Members of an Object

Get-Member!
Easy way to find out what a object can do.

$_ what it is?

$_ represents the current pipeline object and lets you access a property of a piped in object instead of entire project 
get-process | where {$_.name -eq "notepad"} | stop-process

get-service | where {$_.status -eq "stopped"} | start-service -whatif

get-help *operators*

Name                              Category  Module                    Synopsis
----                              --------  ------                    --------
about_Arithmetic_Operators        HelpFile
about_Assignment_Operators        HelpFile
about_Comparison_Operators        HelpFile
about_Logical_Operators           HelpFile
about_Operators                   HelpFile
about_Type_Operators              HelpFile

get-help *comparison*

EQUALITY

-   -eq, -ieq, -ceq - equals
-   -ne, -ine, -cne - not equals
-   -gt, -igt, -cgt - greater than
-   -ge, -ige, -cge - greater than or equal
-   -lt, -ilt, -clt - less than
-   -le, -ile, -cle - less than or equal

MATCHING

-   -like, -ilike, -clike - string matches wildcard pattern
-   -notlike, -inotlike, -cnotlike - string doesn't match wildcard pattern
-   -match, -imatch, -cmatch - string matches regex pattern
-   -notmatch, -inotmatch, -cnotmatch - string doesn't match regex pattern

REPLACEMENT

-   -replace, -ireplace, -creplace - replaces strings matching a regex
    pattern

CONTAINMENT

-   -contains, -icontains, -ccontains - collection contains a value
-   -notcontains, -inotcontains, -cnotcontains - collection doesn't contain
    a value
-   -in - value is in a collection
-   -notin - value isn't in a collection

TYPE

-   -is - both objects are the same type
-   -isnot - the objects aren't the same type

$a = (1, 2) -eq 3
    $a.GetType().Name
    $a.Count

    class MyFileInfoSet : System.IEquatable[Object] {
        [String]$File
        [Int64]$Size

        [bool] Equals([Object] $obj) {
            return ($this.File -eq $obj.File) -and ($this.Size -eq $obj.Size)
        }
    }
    $a = [MyFileInfoSet]@{File = "C:\Windows\explorer.exe"; Size = 4651032}
    $b = [MyFileInfoSet]@{File = "C:\Windows\explorer.exe"; Size = 4651032}
    $a -eq $b

    True

Simple Syntax Example

get-process | where {$_.name -eq "notepad"}
get-process | where {$psitem.name -eq "notepad"}
get-process | where name -eq "notepad"

get-process | ? handlecount -gt 1000

Alias           % -> ForEach-Object
Alias           ? -> Where-Object
Alias           h -> Get-History
Alias           r -> Invoke-History

$_ Advanced Use

$UnattendFile = "unattend.xml"
$xml = [xml](gc $UnattendFile)
$child = $xml.CreateElement("TimeZone", $xml.unattend.NamespaceURI)
$child.InnerXml = "Central Standard Time"
$null = $xml.unattend.settings.Where{($_.Pass -eq 'oobeSystem')}.component.appendchild($child)
#$xml.Save($UnattendFile)
$xml.InnerXml

$resources = Get-AzResourceProvider -ProviderNamespace Microsoft.Compute
$resources.ResourceTypes.Where{($_.ResourceTypeName -eq 'virtualMachines')}.Locations
