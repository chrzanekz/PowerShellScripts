PowerShell MasterClass John’s Savill

Advanced Scripting 

#region Module 5 - Advanced PowerShell Scripting

function first3 {$input | Select-Object -First 3}
get-process | first3

#Code signing
$cert = @(gci cert:\currentuser\my -codesigning)[0]
Set-AuthenticodeSignature signme.ps1 $cert


Lazy with parameters
You don’t have to define the parameters 
Arguments past to the script are captured into default variables
Prefer to use the named parameters

Write-Host ‘Number of argument was: ’
($args.length)
Write-Output ‘ and they were: ‘
Foreach ($arg in $args)
{
	Write-Output $arg
}

Types of parameter
There are 3 types of parameters
Switch parameter -> Get-ChildItem -Recurse
Parameter (Option) -> Get-ChildItem -Filter *.txt
Positional Argument -> Get-ChildItem *.txt

Using Multiple Parameters

Simply add multiple parameters and the variable names are the parameter names
Implicit positions are possible but have to be used in correct order
Alternatively use the parameter names
Param([String]$Greeting, [String]$name)
Write-Host $Greeting $name 

Can explicitly Define Position 
This means the order defined does not have to match that in the parameters 
Note once you use explicit postitional any without a position must be entered by name 

Param([Parameter(Mandatory=$True, Position=2)][String]$Name,
  [Parameter(Mandatory=$True, Position=1)][String]$Greeting)
Write-Host $Greeting $Name
Niezależnie od pobranej kolejności wyświetli to tak jak w skrypcie

Use a different name
Possible to alias parameters to use a alternate names
Can still use a original name
Param([Parameter(Mandatory=$True, Position=2)]
[Alias(“Friend”)][String]$Name,
  [Parameter(Mandatory=$True, Position=1)][String]$Greeting)
Write-Host $Greeting $Name

Switches
Switches are set to true or false with no additional value 
If only switches is present then it means it is true, opposite means false

Param(
[Parameter(Mandatory=$true)][string]$computername,[switch]$showlogprocs)
if($showlogprocs)
{
    Get-CimInstance -class win32_computersystem -ComputerName $computername `
    | fl NumberOfLogicalProcessors,totalphysicalmemory
}
else
{
    Get-CimInstance -class win32_computersystem -ComputerName $computername `
    | fl numberofprocessors,totalphysicalmemory
}

Accepting Pipeline Output

[cmdletbinding()]
Param(
[Parameter(ValueFromPipeline=$true,Mandatory=$true)][String[]]$computers)

<#
.SYNOPSIS
Gets information about passed servers
.DESCRIPTION
Gets information about passed servers using WMI
.PARAMETER computer
Names of computers to scan
.EXAMPLE
CompInfo.ps1 host1, host2
Not very interesting
#>
[cmdletbinding()]
Param(
[Parameter(ValuefromPipeline=$true,Mandatory=$true)][string[]]$computers)
foreach ($computername in $computers)
{
    Write-Verbose "Querying $computername"
    $lookinggood = $true
    try
    {
        $win32CSOut = Get-CimInstance -ClassName win32_computersystem -ComputerName $computername -ErrorAction Stop
    }
    catch
    {
        "Something bad: $_"
        $lookinggood = $false
    }
    if($lookinggood)
    {
        $win32OSOut = Get-CimInstance -ClassName win32_operatingsystem -ComputerName $computername
        Write-Debug "Finished querying $computername"

        $paramout = @{'ComputerName'=$computername;
        'Memory'=$win32CSOut.totalphysicalmemory;
        'Free Memory'=$win32OSOut.freephysicalmemory;
        'Procs'=$win32CSOut.numberofprocessors;
        'Version'=$win32OSOut.version}

        $outobj = New-Object -TypeName PSObject -Property $paramout
        Write-Output $outobj
    }
    else
    {
        Write-Error "Failed for $computername"
    }
}


Enabling Help for script 

<#
.SYNOPSIS
Gets information about passed servers
.DESCRIPTION
Gets information about passed servers using WMI
.PARAMETER computer
Names of computers to scan
.EXAMPLE
CompInfo.ps1 host1, host2
Not very interesting
#>

Get-Help <script_name>

Commenting a section of code -> <# #> 

Troubleshooting

Debugging mode in VS Code 

Write-Verbose
	Shown if add -verbose to command (providing have the [CmdletBinding()]
Write-Debug
	Shown if add -debug to command
	Can also suspend, look at the current state then resume by typing ‘exit’

Write-Verbose "Querying $computername"
    $lookinggood = $true
    try
    {
        $win32CSOut = Get-CimInstance -ClassName win32_computersystem -ComputerName $computername -ErrorAction Stop
    }
    catch
    {
        "Something bad: $_"
        $lookinggood = $false
    }

    if($lookinggood)
    {
        $win32OSOut = Get-CimInstance -ClassName win32_operatingsystem -ComputerName $computername
        Write-Debug "Finished querying $computername"

        $paramout = @{'ComputerName'=$computername;
        'Memory'=$win32CSOut.totalphysicalmemory;
        'Free Memory'=$win32OSOut.freephysicalmemory;
        'Procs'=$win32CSOut.numberofprocessors;
        'Version'=$win32OSOut.version}

        $outobj = New-Object -TypeName PSObject -Property $paramout
        Write-Output $outobj
    }
    else
    {
        Write-Error "Failed for $computername"
    }

Creating your own modules

Saving a file as a PSM1 instead of PS1 makes it PowerShell script Module 
If you save in folder My Documents\WindowsPowershell\Modules\<foldername as PSM1 name\<file>.psm1 it will be available e.g.
My Documents\WindowsPowershell\Modules\CompInfo\CompInfo.psm1

$env:psmodulepath

PSModulePath set when Powershell starts with your My Documents sub folder added automatically 

PSModulePath

System Environment Variable can be changed 
Look at variable will see My Documents folder added
Can add your own static paths. For example I have added d:\project\PowerShell\Module to my system
These are different for Powershell Core which does not inherit currently from Windows PowerShell

More on Functions 

Functions are units of code that can be called elsewhere in the code or the Powershell session
Functions can accept input and output data
Similar fashion to the parameters in the script file and can use $args or named parameters 
There is also a default $input for all data sent to it
Anything sent to output is returned from function (NOT write-host)

Function first3 {$input | Select-Object -First 3}
Get-process | first3

Making it a function

Add function declaration to start of the script with name of the command
Embed all code in {}

Function Get-CompInfo
{
	<# 
	.SYNOPSIS
	Gets information about passed servers
	#> 
	}

Importing your module 

Get-module -listavailable 
If saved correctly will be now visible with get-module -listavailable
Import as normal
Use your command. Autocomplete even works.

Signing your script

Require a code signing certificate 
- Use internal CA 
- Public Trusted CA
- Makecert (although like in all cases not useful outside local testing)
Use Powershell to then sign your script

$cert = @(gci cert:\currentuser\my -codesigning)[0]
Set-AuthenticodeSignature single.ps1 $cert

Set-ExecutionPolicy -ExecutionPolicy AllSigned -> tylko podpisane certyfikaty mogą się wywołać 

Debug with or without VS Code

function Write-OutRPSOption {

    $RPSChoice = Get-Random -Minimum 1 -Maximum 10 #will be less than the max, i.e. 1-9  -   1..1000 | % {Get-Random -Minimum 1 -Maximum 9} | group | select name,count
    Write-Verbose "Random number was $RPSChoice"
    switch ($RPSChoice) {
        {$PSItem -ge 1 -and $PSItem -le 3} { write-output "**   ROCK   **" }
        {$PSItem -ge 4 -and $PSItem -le 6} { write-output "**   PAPER  **" }
        {$PSItem -ge 7 -and $PSItem -le 9} { write-output "** SCISSORS **" }
    }
}

function Start-RPSGame {
    param (
        $NoOfRounds
    )

    $Round = 1

    while($Round -le $NoOfRounds)
    {
        for ($RPSCounterDisp = 1; $RPSCounterDisp -le 3; $RPSCounterDisp++) {
            switch ($RPSCounterDisp) {
                1 { Write-Output "Rock" }
                2 { Write-Output "Paper" }
                3 { Write-Output "Scissors" }
            }
            Start-Sleep -Milliseconds 500
        }

        Write-OutRPSOption

        $Round++
        Write-Output "`n`n"
        Start-Sleep -Seconds 2
    }


}

#Main Execution Block
Write-Output "Three rounds of rock, paper, scissors!"
Start-Sleep -Seconds 1

Write-Output ""

Start-RPSGame(3)

Write-Output "`nThanks for playing"

______________________________

Step into -> every line of code
Step Over -> every line of main code (pomija funkcje wewnetrzne)
Step Out -> opuszcza funkcję i przechodzi do wyższej instancji kodu np. Funkcji

F5 -> Run Debug / Continue
F10 -> Step over
F11 - Step into
Shift F11 -> Step out
Ctrl Shift F5 -> Restart
Shift F5 -> stop
F9 -> set a breakpoint in selected line


Get-PSBreakPoint -> shows us a moment of breaking a piece of code 

Editing Breakpoints -> 
	- Expression ($variable -gt 3)
	- Hit Count (e.g. 3)

Set-PSBreakPoint -script script.ps1 -line 17 

After running a script it would be stop on something a begin process of debugging a script 

H - > help on terminal

L -> whereabout piece of code, where I am in script 

S -> step into like a key in VS Code

V -> step over in terminal 

K -> call stack (you can view the function or procedure calls that are currently on the stack)

*Asterisk can show us where we are in the code in the process of debugging

C - > continue  
O -> step out

Wait-Debugger -> debugger will stop at wait for our action (in code)

Parsing Data and Working with Objects

Storing Credentials 

Many times a credential using is needed
This can be gained online using 
$cred = get-credential
You could also create via code but means plain text!

$user = “administrator”
$password = “p@ssw0rd”
$securepassword = ConvertTo-SecureString $password `
-AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ($user, $securepassword)

Storing an encrypted version

Create a string
$encryptedPassword = ConvertFrom-SecureString (ConvertTo-SecureString -AsPlainText -Force “Password123”)

Make a note of the output and then use that in script
$securePassword = ConvertTo-SecureString “<The huge value from previous command>”

This is still easy to reverse but is harder to quickly write down! 

Store in another file 

Create a file 
$credpath = "c:\temp\MyCredential.xml"
New-Object System.Management.Automation.PSCredential("john@savilltech.com", (ConvertTo-SecureString -AsPlainText -Force "Password123")) | Export-CliXml $credpath

Then in your script
$cred = import-clixml -path $credpath

Azure Key Vault 

Azure make PowerShell better and vice versa 
Azure Key Vault can store various types of data including secrets which can be protected with ACLs
Instead of stored credentials anyway in files, store them in Azure Key Vault
Get-Credential <cred> | Save-AzPSCredential -ResourceGroupName <RG> -VaultName <vault>
$cred = Get-AzPSCredential -VaultName <vault> -Name <cred>

#Using Key Vault
Select-AzSubscription -Subscription (Get-AzSubscription | where Name -EQ "SavillTech Dev Subscription")
$cred = Get-Credential

#Store username and password in keyvault
Set-AzKeyVaultSecret -VaultName 'SavillVault' -Name 'SamplePassword' -SecretValue $cred.Password
$secretuser = ConvertTo-SecureString $cred.UserName -AsPlainText -Force #have to make a secure string
Set-AzKeyVaultSecret -VaultName 'SavillVault' -Name 'SampleUser' -SecretValue $secretuser

#Recreate
$newcred = New-Object System.Management.Automation.PSCredential ($username, $password)
#Test
invoke-command -ComputerName savazuusscdc01 -Credential $newcred -ScriptBlock {whoami}

Certificate Authentication

Certificates can be used for authentication
A User certificate is required for the account which is then exported 
The public key is imported into the target server local computers store under Trusted People 
Create a mapping between cert and a local user
Pass certificate thumbprint when connecting

Variable Types
There are many types of variables
Common ones:
- [string] - unicode string of characters 
- [char] - single 16-bit unicode character
- [byte] - 8-bit character 
- [int] - 32-bit int
- [long] - 64-bit int
- [decimal] - 128-bit decimal value
- [bool] - true or false ($true, $false)
- [DateTime] - date and time

Casting and checking

Variable types can be automatically set based on the value set
- $number = 42
- $boolset=$true
- $stringval=“hello”
- $charval =‘a’ (it doesn’t work, you need to force that)

#Var types
$number=42
$boolset=$true
$stringval="hello"
$charval='a'
$number.GetType()
$boolset.GetType()
$stringval.GetType()
$charval.GetType()

Can force variable to be a certain type:
[char]$charval = ‘a’

View the type of variable with $var.gettype()

Can also test:
42 -is [int]

String

Does a string contain another string 
You do NOT want -conatins (this checks if a collection of objects includes an object)
Use -Like
$string1 = “the quick brown fox jumped over the lazy dog”
$string1 -like “*fox*” 
$string2 = $string1 + “ who was not amused”

Time
$today = get-date
$today | Select-Object -ExpandProperty DayOfWeek
[DateTime]::ParseExact(“02-25-2011”,”MM-dd-yyyy”,[System.Globalization.CultureInfo]::InvariantCulture)
$christmas=[system.datetime]”25 December 2019” 
($christmas - $today).Days
$today.AddDays(-60)
$a = new-object system.globalization.datetimeformatinfo
$a.DayNames

Variable Scope 

Variables can have a scope
By default a variable has local scope and is visible in the scope its created and any Child scopes
Possible to specify alternate scopes 
Local -> Current scope and child scopes 
Global -> Accessible in all scopes 
Script -> Available within a script scope only 
Private -> Cannot be seen outside the current scope (not children)

#Variable Scope
function test-scope()
{
    write-output $defvar
    write-output $global:globvar
    write-output $script:scripvar
    write-output $private:privvar
    $funcvar = "function"
    $private:funcpriv = "funcpriv"
    $global:funcglobal = "globfunc"
}

$defvar = "default/local" #default
get-variable defvar -scope local
$global:globvar = "global"
$script:scripvar = "script"
$private:privvar = "private"
test-scope
$funcvar
$funcglobal #this should be visible

Variables with Invoke-Command

Something interesting happens using variables and Invoke-Command
$message = “message” 
Invoke-Command -ComputerName comp_name -ScriptBlock {Write-host $message} 

The Invoke-Command creates a new session that does not have the variables. Instead the variables must be passed.
$ScriptBlockContent = {
    param ($MessageToWrite)
    Write-Host $MessageToWrite }
Invoke-Command -ComputerName savazuusscdc01 -ScriptBlock $ScriptBlockContent -ArgumentList $message
#or
Invoke-Command -ComputerName savazuusscdc01 -ScriptBlock {Write-Output $args} -ArgumentList $message

Using $using

PowerShell 3 introduces a new way to utilize local scope variables with Invoke-Command, $using
Invoke-Command -ComputerName savazuusscdc01 -ScriptBlock {Write-Host $using:message}

HashTables
Useful to store names/value pairs
#Hash Tables
$favthings = @{"Julie"="Sushi";"Ben"="Trains";"Abby"="Princess";"Kevin"="Minecraft"}
$favthings.Add("John","Crab Cakes")
$favthings.Set_Item("John","Steak") -> change a value
$favthings.Get_Item("Abby")

Using PSObject 
PSObject enables you to create a custom object 
There is also System.Object but custom properties tend to get lost with .NET functions which is bad 
With PSObject add a new properties and a value for the new property 
Can add many properties and values as desired 
Useful way to return multiple pieces of data when only a single object can be returned 

#Custom objects
$cusobj = New-Object PSObject
Add-Member -InputObject $cusobj -MemberType NoteProperty `
    -Name greeting -Value "Hello"

$favthings = @{"Julie"="Sushi";"Ben"="Trains";"Abby"="Princess";"Kevin"="Minecraft"}
$favobj = New-Object PSObject -Property $favthings
#In PowerShell v3 can skip a step
$favobj2 = [PSCustomObject]@{"Julie"="Sushi";"Ben"="Trains";"Abby"="Princess";"Kevin"="Minecraft"}

ForEach-Object
Sometimes the limitations of $_ and the pipeline (even with ;) means we need something more
Typical to save the results to an array and then examine each element in the array 
$names = @{“Julie”, “Abby”, “Ben”, “Kevin”}
$names | ForEach-Object -Process {Write-Output $_ }
$names | ForEach -Process {Write-Output $_ }
$names | ForEach {Write-Output $_ }
$names | % {Write-Output $_ }

ForEach =/= ForEach
ForEach is an alias for ForEach-Object when data is pipelined to it
When data is not pipelined to it then it’s a Powershell statement that behaves differently
ForEach loads all objects into a collection first so uses more memory but may enable better optimization of data loading and execute faster
ForEach-Object continues data down the pipeline while ForEach does not
ForEach ($name in $names) {Write-Output $name}

#Foreach vs Foreach
ForEach-Object -InputObject (1..100) {
    $_
} | Measure-Object

ForEach ($num in (1..100)) {
    $num
} | Measure-Object

'Z'..'A'

Getting Property Values
<object>.<property> typically gives you what you need (value)
$town.name
$_.id
Sometimes this doesn’t work as expected 

#Accessing property values
$samacctname = "John"
Get-ADUser $samacctname  -Properties mail
Get-ADUser $samacctname  -Properties mail | select-object mail
Get-ADUser $samacctname  -Properties mail | select-object mail | get-member
Get-ADUser $samacctname  -Properties mail | select-object -ExpandProperty mail | get-member
Get-ADUser $samacctname  -Properties mail | select-object -ExpandProperty mail


Desired State Configuration

Why we need DSC

Applying configuration to an OS can be complex 
- OS configurations 
- Roles and features to install
- Role/feature configuration
- Application to install and configure
- Files, registry etc. requirements 
We don’t want specific OS images with app configurations
Vanilla OS then apply configuration post creation
Posiible to achieve this through PowerShell script during setup but what if someone changes it

DSC

Powershell v4 brings Desired State Configuration Management completing the Powershell initial vision
Initially 12 providers based around objects such as registry, files, environment, scripts, users, groups and so on
Many additional providers available
Declarative rather than imperative 
Not currently available in Powershell Core

Regular Imperative PowerShell

You have to handle all error-handling, checking if may have already run parts of it

Import-Module Server-Manager
#Check and install Web Server Role if not installed 
If (-not (Get-WindowsFeature “WebServer”).Installed)
{
	try {
		Add-WindowsFeature WebServer
	}
	catch {
		Write-Error $_
	}
}

Declarative Powershell DSC

Only focus on the desire state 

#Install Windows The IIS role 
WindowsFeature IIS
{
	Ensure		= “Present”
	Name		= “Web-Server”
}

Phases of using DSC

Authoring 
- Creating the DSC File
- Compile to MOF file which is DMTF standard
Staging 
- The DSC is staged on the target using one of two models (push or pull)
“Make it so “
- COnfiguration is applied to the local configuration store which contains all of DSC
- The configuration is then parsed and the relevant WMI providers implement required changes 
- Idempotent so can be repeatedly applied with our causing damage  

Models of using DSC

DSC application can be used in one of two modes 
Push
- Configurations are applied to a servers via Start-DSCConfiguration immediately 
Pull
- Configuration are centrally stored 
- Special service, DSC-Service, runs on Windows Server 2012 R2
- Servers are configured for pull mode which consists of a unique configuration ID (GUID) and the DSC server to pull from
- Server poll and pull their configuration from the central DSC Service 

Configuration resources 

Archive resource 
Environment resource 
File resource 
Group resource 
Log resource 
Package resource 
Registry resource
Script resource
Service resource 
User Resource 
Windows Feature resource
Windows Process resource 

Get-DSCResource -> komenda 

DSC Resource Kit

Additional configuration resources are constantly being added
These were released as DSC Resource Kit
Now available via PowerShell Gallery 
Large number resources including SQL Server, Exchange, Remote Desktop Services, Hyper-V, System Center and more!
Serach for tag DSCResourceKit

Find-Module -tag dscresourcekit | install-Module 
Get-DSCResource

DSCConfiguration Format

Outermost Configuration block can contain passed parameters then 
- Zero or more Node blocks that define:
    - One or more Resource blocks

Configuration WebConfig
{
	param([string[]]$computername=‘localhost’) #optional parameters

	Node $computername #zero or more node blocks 
	{
		WindowsFeature WebServer #one or more resource blocks
		{
			Ensure = “Present” #uninstall the role, set Ensure to “absent”
			Name = “Web-Server”
		}
	}
}

Basic DSC Usage 

A DSC file mus be compiled to MOF format by executing the name of the configuration
The configuration is then applied (in the push model) using
- Start-DscConfiguration -Wait -Verbose -Path .\MyTestFileConfig 
The Configuration can be checked  using Get-DscConfiguration
To look for drift use Test-DscConfiguration
To see actual drift add -Detailed to Test-DscConfiguration, needs WMF5

Get-WindowsFeature

SIMPLE SCRIPT 

_____________________________________________________>
Set-ExecutionPolicy unrestricted -Force

Enable-PSRemoting -Force

# uses http://gallery.technet.microsoft.com/scriptcenter/xWebAdministration-Module-3c8bb6be

#Copy the modules to the folder
$username = "savillmasterazurestore"
$password = convertto-securestring -String "R6yw==" -AsPlainText -Force
$cred = new-object -typename System.Management.Automation.PSCredential `
         -argumentlist $username, $password

New-PSDrive –Name T –PSProvider FileSystem –Root “\\savillmasterazurestore.file.core.windows.net\tools” -Credential $cred
Copy-Item -Path "T:\DSC\xWebAdministration" -Destination $env:ProgramFiles\WindowsPowerShell\Modules -Recurse
Remove-PSDrive -Name T

Configuration SavillTechWebsite 
{
    param 
    ( 
        # Target nodes to apply the configuration 
        [string[]]$NodeName = 'localhost' 
    ) 
    # Import the module that defines custom resources 
    Import-DscResource -Module xWebAdministration 
    Node $NodeName 
    { 
        # Install the IIS role 
        WindowsFeature IIS 
        { 
            Ensure          = "Present" 
            Name            = "Web-Server" 
        } 
        #Install ASP.NET 4.5 
        WindowsFeature ASPNet45 
        { 
          Ensure = “Present” 
          Name = “Web-Asp-Net45” 
        } 
        # Stop the default website 
        xWebsite DefaultSite  
        { 
            Ensure          = "Present" 
            Name            = "Default Web Site" 
            State           = "Stopped" 
            PhysicalPath    = "C:\inetpub\wwwroot" 
            DependsOn       = "[WindowsFeature]IIS" 
        } 
        # Copy the website content 
        File WebContent 
        { 
            Ensure          = "Present" 
            SourcePath      = "C:\Program Files\WindowsPowerShell\Modules\xWebAdministration\SavillSite"
            DestinationPath = "C:\inetpub\SavillSite"
            Recurse         = $true 
            Type            = "Directory" 
            DependsOn       = "[WindowsFeature]AspNet45" 
        }
        # Create a new website 
        xWebsite SavTechWebSite  
        { 
            Ensure          = "Present" 
            Name            = "SavillSite"
            State           = "Started" 
            PhysicalPath    = "C:\inetpub\SavillSite" 
            DependsOn       = "[File]WebContent" 
        }
    } 
}

SavillTechWebsite -MachineName localhost

Start-DscConfiguration -Path .\SavillTechWebsite -Wait -Verbose

_________________________________________________________>


#Set-ExecutionPolicy unrestricted -Force
#Enable-PSRemoting -Force

#uses https://www.powershellgallery.com/packages/xWebAdministration/2.4.0.0
Install-Module -Name xWebAdministration

Configuration SavillTechWebsite
{
    param
    (
        # Target nodes to apply the configuration
        [string[]]$NodeName = 'localhost'
    )
    Import-DscResource –ModuleName 'PSDesiredStateConfiguration'
    # Import the module that defines custom resources
    Import-DscResource -Module xWebAdministration
    Node $NodeName
    {
        # Install the IIS role
        WindowsFeature IIS
        {
            Ensure          = "Present"
            Name            = "Web-Server"
        }
        #Install ASP.NET 4.5
        WindowsFeature ASPNet45
        {
          Ensure = “Present”
          Name = “Web-Asp-Net45”
        }
        # Stop the default website
        xWebsite DefaultSite
        {
            Ensure          = "Present"
            Name            = "Default Web Site"
            State           = "Stopped"
            PhysicalPath    = "C:\inetpub\wwwroot"
            DependsOn       = "[WindowsFeature]IIS"
        }
        # Copy the website content
        File WebContent
        {
            Ensure          = "Present"
            SourcePath      = "C:\Source\SavillSite"
            DestinationPath = "C:\inetpub\SavillSite"
            Recurse         = $true
            Type            = "Directory"
            DependsOn       = "[WindowsFeature]AspNet45"
        }
        # Create a new website
        xWebsite SavTechWebSite
        {
            Ensure          = "Present"
            Name            = "SavillSite"
            State           = "Started"
            PhysicalPath    = "C:\inetpub\SavillSite"
            DependsOn       = "[File]WebContent"
        }
    }
}

#Create the MOF
SavillTechWebsite -NodeName localhost

#Apply the configuration
Start-DscConfiguration -Path .\SavillTechWebsite -Wait -Verbose

#Test
$IE=new-object -com internetexplorer.application
$IE.navigate2("127.0.0.1")
$IE.visible=$true

#View the configuration
Get-DscConfiguration

#Remove if wanted but does not roll back the changes
Remove-DscConfigurationDocument -Stage Current
Remove-WindowsFeature -Name Web-Server
Remove-Item -Path C:\inetpub\*.* -Recurse -Force

_________________________________________________________________>

Compliance of DSC

Often you will need to understand the deployment status of DSC
Also the configuration drift knowledge centrally stored is very valuable 
A solution is being created that will be available as open source on GitHub and the PowerShell Gallery
- DSC Environment Analyzer (DSC-EA)

DSC for any machine 

Typically DSC file specifies a specific target node for configuration
- Node websrv1 { …… }
For configuration to apply to any server use localhost
- Node localhost { ……. }
Alternatively use a parameter to pass in the node name that is set at compilation time 
- Param([string[]]$NodeName=‘localhost’)
       Node $NodeName
	{ ……… }

Controlling Local Configuration

The frequency of the refresh can be modified from the defaults such as:
- Configuration Mode (apply, apply and monitor, apply and correct)
- Refresh mode (push vs pull)
- Refresh frequency
- How often to apply configuration (must be multiple of the refresh)

Local Configuration Example

Configuration DemoConfig
{
	Node ‘localhost’
	{
		LocalConfigurationManager
		{
			ConfigurationMode = “ApplyandAutoCorrrect”
			ConfigurationModeFrequencyMins = 30
			RefreshFrequencyMins = 30 #30 is minimum
		}
	}
}

DemoConfig -OutputPath “C:\users\administrator.SAVILLTECH\dsc”

Set-DscLocalConfigurationManager -Path “C:\users\administrator.SAVILLTECH\dsc” -Verbose

Get-DscLocalConfigurationManager 

Handling Files With The File Configuration Resource 

When using the File configuration resource to ensure a target folder is the same as source the source list is compiled at application time
To keep target the same as the source is updated need to add
MatchSource = $true

File MyExample 
{
	Ensure = “Present”
	Type = “Directory”
	Recurse = $true
	MatchSource =$true
	SourcePath: ……
	DestinationPath: ………
}

PowerShell DSC use in Azure

Can use DSC with Azure VM like any other OS instance
Can also be used when provisioning a VM
Can use VM Extensions to trigger via Powershell for running VM

$hostname = (hostname).ToUpper()

Write-Verbose -Verbose:$true "[$hostname] Starting the node configuration"

#Set-ExecutionPolicy unrestricted -Force #This is set automatically when called by Azure script extension

Write-Verbose -Verbose:$true "[$hostname] Enabling Remoting"

Enable-PSRemoting -Force

# uses http://gallery.technet.microsoft.com/scriptcenter/xWebAdministration-Module-3c8bb6be

Write-Verbose -Verbose:$true "[$hostname] Copying content from Azure Files to PowerShell Modules path"

#Copy the modules to the folder
$username = "savillmasterazurestore"
$password = convertto-securestring -String "R6yw==" -AsPlainText -Force
$cred = new-object -typename System.Management.Automation.PSCredential `
         -argumentlist $username, $password

New-PSDrive –Name T –PSProvider FileSystem –Root “\\savillmasterazurestore.file.core.windows.net\tools” -Credential $cred
Copy-Item -Path "T:\DSC\xWebAdministration" -Destination $env:ProgramFiles\WindowsPowerShell\Modules -Recurse
Remove-PSDrive -Name T

Write-Verbose -Verbose:$true "[$hostname] Applying DSC Configuration"

$configString=@"
Configuration SavillTechWebsite 
{
    param 
    ( 
        # Target nodes to apply the configuration 
        [string[]]`$NodeName = `'localhost`' 
    ) 
    # Import the module that defines custom resources 
    Import-DscResource -Module xWebAdministration 
    Node `$NodeName 
    { 
        # Install the IIS role 
        WindowsFeature IIS 
        { 
            Ensure          = `"Present`" 
            Name            = `"Web-Server`" 
        } 
        #Install ASP.NET 4.5 
        WindowsFeature ASPNet45 
        { 
          Ensure = `“Present`” 
          Name = `“Web-Asp-Net45`” 
        } 
        # Stop the default website 
        xWebsite DefaultSite  
        { 
            Ensure          = `"Present`" 
            Name            = `"Default Web Site`" 
            State           = `"Stopped`" 
            PhysicalPath    = `"C:\inetpub\wwwroot`" 
            DependsOn       = `"[WindowsFeature]IIS`" 
        } 
        # Copy the website content 
        File WebContent 
        { 
            Ensure          = `"Present`" 
            SourcePath      = `"C:\Program Files\WindowsPowerShell\Modules\xWebAdministration\SavillSite`"
            DestinationPath = `"C:\inetpub\SavillSite`"
            Recurse         = `$true 
            Type            = `"Directory`" 
            DependsOn       = `"[WindowsFeature]AspNet45`" 
        }
        # Create a new website 
        xWebsite SavTechWebSite  
        { 
            Ensure          = '"Present`" 
            Name            = `"SavillSite`"
            State           = `"Started`" 
            PhysicalPath    = `"C:\inetpub\SavillSite`" 
            DependsOn       = `"[File]WebContent`" 
        }
    } 
}
"@
Invoke-Expression $configString 


SavillTechWebsite -MachineName localhost

Start-DscConfiguration -Path .\SavillTechWebsite -Wait -Verbose




TroubleShooting

Make sure you enable remoting in your script 
Do not require any interaction
Write-Verbose in your script to aid troubleshooting 
Give it time. The script is run asynchronously so the VM may show as provisioned but your script may still be running in the background even after you connect to it 
View logs within VM at -> C:\WindowsAzure\Logs\Plugins\Microsoft.Compute.CustomScriptExtension\<version e.g. 11>
- CustomScriptHandler.log - your file execution

One Configuration per Machine

Mostly
PowerShell v5 introduces multiple partial configurations that can be combined to a single MOF prior to application
Outside of this you can only have one configuration per machine

configuration WebConfig
{
    Node IsWebServer
    {
        WindowsFeature IIS
        {
            Ensure               = 'Present'
            Name                 = 'Web-Server'
            IncludeAllSubFeature = $true
        }
    }

    Node NotWebServer
    {
        WindowsFeature IIS
        {
            Ensure               = 'Absent'
            Name                 = 'Web-Server'
        }
    }
} 
