PowerShell dla zaawansowanych

Od linii poleceń do skryptu - MODUL 1

Prosty pierwszy skrypt

$a=ls *.txt
$a | % {cat $_.fullname}

Jest to statyczny skrypt, wiec niepotrzebnie go przechowywać w pliku ps1, powinny być dynamiczne argumenty, które eliminują powatarzalne czynności, jakieś parametry itd.

Function wyswietl {
$a=ls *.txt
$a | % {cat $_.fullname}
}

What is DOT sourcing?
. ./script.ps1
Wczytywanie skryptu do pamięci, czyli tak jak wspominali -> wczytanie powyższej funkcji do pamięci w linii poleceń powershella, aby można ja było wykorzystać. Wzięte z linuxa

Można do profilu do dorzucić, aby później na codzień z tego wykorzystywać 

function get-ObjectInfo {
	“hello world”
}

Get-oInfo.ps1
. .\Get-oInfo.ps1

OUTPUT
Hello world

Argumenty

function get-ObjectInfo {
	“hello world”
	$args
}

Get-oInfo.ps1
. .\Get-oInfo.ps1

Get-ObjectInfo abc def

OUTPUT
Hello world
abc
Def

Argumenty to są tablice, wiec każdy element został literowany i wyświetlony

function get-ObjectInfo {
	“hello world”
	$args[0]
}

Z argumentów się nie korzysta, ponieważ dane musza być podane według kolejności, inaczej skrypt może narobić cos złego! Dane są wstrzykiwane w kolejności 

Parametry

function get-ObjectInfo {
	param(
		$string
	)
	“hello world”
	$args
}

Po naciśnięciu ctrl spacja pokazuje się get-ObjectInfo -string (parametr)

function get-ObjectInfo {
	param(
		$string
	)
	$string
	$args
}

get-ObjectInfo -string “hello world”
OUTPUT
Hello world

get-ObjectInfo -string “hello world” def ghi
OUTPUT
Hello world
Def
Ghi

Jeżeli jest cos zdefiniowane jako parametr to argumenty tego nie widzą!


function get-ObjectInfo {
	param(
		$string,
		$string2
	)
	write-host -foregroundcolor Yellow $string
	write-host -foregroundcolor Red $string2 
	$args
}

function get-ObjectInfo {
	param(
		$userName,
		$computerName
	)
	write-host -foregroundcolor Yellow $userName
	write-host -foregroundcolor Red $computerName
	$args
}

Można używać skróconych wersji parametrów -u -s i podać parametry

function get-ObjectInfo {
	param(
		[int]$userName,
		[string]$computerName
	)
	write-host -foregroundcolor Yellow $userName
	write-host -foregroundcolor Red $computerName
	$args
}

Zabezpieczanie wprowadzanych danych do skryptu w parameterach 

Zabezpieczamy przed podaniem złego formatu danych

function get-ObjectInfo {
	param(
		[string]$userName,
		[string]$computerName
	)
	write-host -foregroundcolor Yellow $userName
	write-host -foregroundcolor Red $computerName
	$args
}

Zabezpieczamy przed niepodaniem żadnego parametru

param(
	[Parameter(Mandatory=$true)][string]$userName,
	[string]$computerName
)
write-host -foregroundcolor Yellow $userName
write-host -foregroundcolor Red $computerName
$args

Odwrotna kolejność wykonywania parametrów

param(
	[Parameter(Position=2)][string]$userName,
	[Parameter(Position=1)][string]$computerName
)
write-host -foregroundcolor Yellow $userName
write-host -foregroundcolor Red $computerName
$args

Jeśli w tym skrypcie wyżej podamy dodatkowy parametr (argument) to się on nie wyświetli, dlatego ponieważ skrypt w wyniku podania szczegółów na temat parametrów przeszedł w tryb Advanced Parameters.
Argumenty nie są w takiej funkcji już obsługiwane.

Trochę artykułów na temat funkcji w samym powershellu w module HELP

Man about_functions*
Man about_functions* | select -expandProperty name
Man about_functions_Advanced_parameters -ShowWIndow 

[cmdletbinding()]
param(
	[Parameter(Position=2)][string]$userName,
	[Parameter(Position=1)][string]$computerName
)
write-host -foregroundcolor Yellow $userName
write-host -foregroundcolor Red $computerName
$args

MODUŁ 2 - Budowanie funkcji oraz skryptów

[cmdletbinding()]
param(
	[Parameter(Position=2, Mandatory=$true)][string]$userName,
	[Parameter(Position=1)][string]$computerName
)
write-host -foregroundcolor Yellow $userName
write-host -foregroundcolor Red $computerName
$args

Cmdletbinding podłącza takie komendy jak Verbose, Debug, ErrorAction itd.

ParameterSet

[cmdletbinding()]
param(
	[Parameter(ParameterSetName=‘user’)]
		[string]$userName,
	[Parameter(ParameterSetName=‘user’)]
		[int]$wiek,
	[Parameter(ParameterSetName=‘computer’)]
		[string]$computerName
	[Parameter(ParameterSetName=‘computer’)]
		[string]$platforma
)
write-host -foregroundcolor Yellow $userName
write-host -foregroundcolor Red $computerName

Sety pozwalają tylko na wybór konkretnego setu i tylko tego setu do wywołania poszczególnego skryptu/funkcji. Można wymusić, ale ostatecznie i tak skrypt wywali ERROR.

$PSCmdlet | gm
Zasada działania:
Każde wywołanie tego CMDletu zawiera obiekt związany z tablicami, a każdy punkt tablicy ma kolejne obiekty związane z kolejnymi informacjami i parametrami.

W tym przypadku będzie nas interesować: “ParameterSetName”. Dodajemy logikę: 

[cmdletbinding()]
param(
	[Parameter(ParameterSetName=‘user’)]
		[string]$userName,
	[Parameter(ParameterSetName=‘user’)]
		[int]$wiek,
	[Parameter(ParameterSetName=‘computer’)]
		[string]$computerName
	[Parameter(ParameterSetName=‘computer’)]
		[string]$platforma
)
switch($PSCmdlet.ParameterSetName) {
	‘computer’ {
		write-host -foregroundcolor Red $computerName
		write-host -foregroundcolor Cyan $platfroma
	}
	‘user’ {
		write-host -foregroundcolor Yellow $userName
		write-host -foregroundcolor Cyan $wiek
	}
}

Ustawienie domyślnego zestawu parametrów oraz wykonanie skryptu przez ustawienie pozycji.
Dodatkowo zabezpieczenie ValidateRange przed podaniem nieprawidłowych wartości parametru i określenie jego zakresu.

[cmdletbinding(DefaultParameterSetName=‘user’)]
param(
	[Parameter(mandatory=$true,ParameterSetName=‘user’,position=0)]
		[string]$userName,
	[Parameter(ParameterSetName=‘user’,position=1)]
		[ValidateRange(18,120)]
		[int]$wiek,
	[Parameter(ParameterSetName=‘user’,position=2)]
		[ValidateSet(“K”, “M”)]
		[string]$plec,
	[Parameter(mandatory=$true,ParameterSetName=‘computer’,position=0)]
		[string]$computerName
	[Parameter(ParameterSetName=‘computer’,position=1)]
		[string]$platforma
)
switch($PSCmdlet.ParameterSetName) {
	‘computer’ {
		write-host -foregroundcolor Red $computerName
		write-host -foregroundcolor Cyan $platfroma
	}
	‘user’ {
		write-host -foregroundcolor Yellow $userName
		write-host -foregroundcolor Cyan $wiek
	}
}

.\Get-oInfo.ps1 55 user -plec K

REGEXP in PowerShell oraz zmienna globalna (parametr)

[cmdletbinding(DefaultParameterSetName=‘user’)]
param(
	[ValidatePattern(“^.*\.(txt|csv)$”)]
		[string]$filename,

	[Parameter(mandatory=$true,ParameterSetName=‘user’,position=0)]
		[string]$userName,
	[Parameter(ParameterSetName=‘user’,position=1)]
		[ValidateRange(18,120)]
		[int]$wiek,
	[Parameter(ParameterSetName=‘user’,position=2)]
		[ValidateSet(“K”, “M”)]
		[string]$plec,
	[Parameter(mandatory=$true,ParameterSetName=‘computer’,position=0)]
		[string]$computerName
	[Parameter(ParameterSetName=‘computer’,position=1)]
		[string]$platforma
)
Write-host “zczytujemy plik: $filename“
switch($PSCmdlet.ParameterSetName) {
	‘computer’ {
		write-host -foregroundcolor Red $computerName
		write-host -foregroundcolor Cyan $platfroma
	}
	‘user’ {
		write-host -foregroundcolor Yellow $userName
		write-host -foregroundcolor Cyan $wiek
	}
}

.\get-oinfo.ps1 -filename plik.csv -username user

Dodatkowe parametry jakie możemy weryfikować:
- ValidateLength
- ValidateCount
- ValidatePattern
- ValidateRange
- ValidateScript 
- ValidateNotNull 

Get-help .\get-oinfo.ps1
Wyświetli nam podstawowy help, jakie parametry możemy przekazać do tego skryptu

HELP DO SKRYPTU
Ważna informacja, żeby oddzielić help do funkcji trzeba mieć puste trzy linie za napsianym helpem

<#
	.SYNOPSIS
	teścik
	.DESCRIPTION
	na potrzeby MVA pokazuje jak się pisze help, tak aby były samo dokumentujące się 
	comment based help
	.EXAMPLE
	podstawowe wywołanie skryptu
	test09
	.EXAMPLE
	test09 name -wiek $([datetime]”1985-03-01”)
	.EXAMPLE
	test09 -computerName “myWin” “w10”
	.PARAMETER nazwaUsera
	jakaś nazwa użytkownika
	.PARAMETER dataUrodzenia
	opisywanie niektórych parametrów nie ma sensu, wiadomo ze nazwa urodzenia
	.PARAMETER nazwaKomputera
	chodzi o nazwę komputera
	.PARAMETER systemOperacyjny
	nazwa systemu operacyjnego np. Win10
	.NOTES
	author: mati 2023
	warto tu pisać changeloga, jeśli chcemy trzymać wersje skryptu
	.LINK
	http://hlwnv.netlify.com
#> 

[cmdletbinding(DefaultParameterSetName=‘user’)]
param(
	#ten parametr opisuje wciąganie pliku do skryptu
	[ValidatePattern(“^.*\.(txt|csv)$”)]
		[string]$filename,
	#ten parametr opisuje nazwę użytkownika 
	[Parameter(mandatory=$true,ParameterSetName=‘user’,position=0)]
		[string]$userName,
	#ten parametr opisuje wiek użytkownika
	[Parameter(ParameterSetName=‘user’,position=1)]
		[ValidateRange(18,120)]
		[int]$wiek,
	#wiek użytkownika 
	[Parameter(ParameterSetName=‘user’,position=2)]
		[ValidateSet(“K”, “M”)]
		[string]$plec,
	#komputer
	[Parameter(mandatory=$true,ParameterSetName=‘computer’,position=0)]
		[string]$computerName
	#system operacyjny
	[Parameter(ParameterSetName=‘computer’,position=1)]
		[string]$platforma
)
Write-host “zczytujemy plik: $filename“
switch($PSCmdlet.ParameterSetName) {
	‘computer’ {
		write-host -foregroundcolor Red $computerName
		write-host -foregroundcolor Cyan $platfroma
	}
	‘user’ {
		write-host -foregroundcolor Yellow $userName
		write-host -foregroundcolor Cyan $wiek
	}
}

MODUŁ 3 - STRUMIENIE DANYCH

Przekazywanie parametrów 
Bloki skryptu

[cmdletbinding(DefaultParameterSetName=‘user’)]
param(
	#ten parametr opisuje wciąganie pliku do skryptu
	[ValidatePattern(“^.*\.(txt|csv)$”)]
		[string]$filename,
	#ten parametr opisuje nazwę użytkownika 
	[Parameter(mandatory=$true,ParameterSetName=‘user’,position=0,valueFromPiepline= $true)]
		[string]$userName,
	#ten parametr opisuje wiek użytkownika
	[Parameter(ParameterSetName=‘user’,position=1)]
		[ValidateRange(18,120)]
		[int]$wiek,
	#wiek użytkownika 
	[Parameter(ParameterSetName=‘user’,position=2)]
		[ValidateSet(“K”, “M”)]
		[string]$plec,
	#komputer
	[Parameter(mandatory=$true,ParameterSetName=‘computer’,position=0)]
		[string]$computerName
	#system operacyjny
	[Parameter(ParameterSetName=‘computer’,position=1)]
		[string]$platforma
)
Write-host “zczytujemy plik: $filename“
switch($PSCmdlet.ParameterSetName) {
	‘computer’ {
		write-host -foregroundcolor Red $computerName
		write-host -foregroundcolor Cyan $platfroma
	}
	‘user’ {
		write-host -foregroundcolor Yellow $userName
		write-host -foregroundcolor Cyan $wiek
	}
}

PIPELINENING

KOMENDY wywoływane:

‘userName’ | ./get-oInfo.ps1 -> nie zadziała ta funkcja ponieważ nie przekazuje danych, bo nie wie dokąd je przekazać

‘userName’ | %{.\get-oInfo.ps1 $_} -> to zadziała ponieważ został przekazany parametr Mandatory do skryptu i skrypt wykonał się prawidłowo
% -> forEach-Object

Po wprowadzeniu parametru valueFromPipeline = $true -> przekazywanie bezpośrednio do skryptu z pipeline’a działa valueFromPiepline= $true in Parameter.

ValueFromPipeline -> działa tylko w związku z przekazaniem jednej wartości, a nie szeregu tych wartości :D

$user = new-Object -typename psobject -property @{ComputerName=‘MyComp’; platforma=‘win10’ }

‘User’ | gm -> jedyne property to Length i takiej rzeczy szuka PowerShell

 [cmdletbinding(DefaultParameterSetName=‘user’)]
param(
	#ten parametr opisuje wciąganie pliku do skryptu
	[ValidatePattern(“^.*\.(txt|csv)$”)]
		[string]$filename,
	#ten parametr opisuje nazwę użytkownika 
	[Parameter(mandatory=$true,ParameterSetName=‘user’,position=0,valueFromPieplineByPropertyName= $true)]
		[string]$userName,
	#ten parametr opisuje wiek użytkownika
	[Parameter(ParameterSetName=‘user’,position=1,valueFromPieplineByPropertyName= $true)]
		[ValidateRange(18,120)]
		[int]$wiek,
	#wiek użytkownika 
	[Parameter(ParameterSetName=‘user’,position=2, valueFromPieplineByPropertyName= $true)]
		[ValidateSet(“K”, “M”)]
		[string]$plec,
	#komputer
	[Parameter(mandatory=$true,ParameterSetName=‘computer’,position=0, valueFromPieplineByPropertyName= $true)]
		[string]$computerName
	#system operacyjny
	[Parameter(ParameterSetName=‘computer’,position=1, valueFromPieplineByPropertyName= $true)]
		[string]$platforma
)
Write-host “zczytujemy plik: $filename“
switch($PSCmdlet.ParameterSetName) {
	‘computer’ {
		write-host -foregroundcolor Red $computerName
		write-host -foregroundcolor Cyan $platforma
	}
	‘user’ {
		write-host -foregroundcolor Yellow $userName
		write-host -foregroundcolor Cyan $wiek
	}
}

valueFromPieplineByPropertyName= $true -> oznacza przekazywanie danych na podstawie nazwy Property w skrypcie

ValueFromPipeline -> działa tylko w związku z przekazaniem jednej wartości, a nie szeregu tych wartości :D

TWORZYMY NOWY OBIEKT Z HASHTABLE, ABY PRZEKAZAC WARTOSCI DO SKRYPTU
$user = new-Object -typename psobject -property @{ComputerName=‘MyComp’; platforma=‘win10’ }

‘User’ | gm -> jedyne property to Length i takiej rzeczy szuka PowerShell

./get-oInfo.ps1 -computerName $user.computerName -platforma $user.platforma -> będzie to samo

Get-service | ? Name -match ‘netlogon’

Można doinstalowywać rozszerzenia do PowerShella w postaci bibliotek .dll, np. Do obsługi plików MS Office, np. Do implementacji pliku excelowego i pipeowania danych do skryptu. Nazywa się EPPlus.dll

________________________

Function new-obj {
 [cmdletbinding(DefaultParameterSetName=‘user’)]
param(
	#ten parametr opisuje wciąganie pliku do skryptu
	[ValidatePattern(“^.*\.(txt|csv)$”)]
		[string]$filename,
	#ten parametr opisuje nazwę użytkownika 
	[Parameter(mandatory=$true,ParameterSetName=‘user’,position=0,valueFromPieplineByPropertyName= $true)]
		[string]$userName,
	#ten parametr opisuje wiek użytkownika
	[Parameter(ParameterSetName=‘user’,position=1,valueFromPieplineByPropertyName= $true)]
		[ValidateRange(18,120)]
		[int]$wiek,
	#wiek użytkownika 
	[Parameter(ParameterSetName=‘user’,position=2, valueFromPieplineByPropertyName= $true)]
		[ValidateSet(“K”, “M”)]
		[string]$plec,
	#komputer
	[Parameter(mandatory=$true,ParameterSetName=‘computer’,position=0, valueFromPieplineByPropertyName= $true)]
		[string]$computerName
	#system operacyjny
	[Parameter(ParameterSetName=‘computer’,position=1, valueFromPieplineByPropertyName= $true)]
		[string]$platforma
)
Write-host “zczytujemy plik: $filename“
switch($PSCmdlet.ParameterSetName) {
	‘computer’ {
		write-host -foregroundcolor Red $computerName
		write-host -foregroundcolor Cyan $platforma
	}
	‘user’ {
		write-host -foregroundcolor Yellow $userName
		write-host -foregroundcolor Cyan $wiek
	}
}
}

$comp = @{
	ComputerName = ‘MyComp’
	platforma = ‘win10’
}

New-obj @comp

____________________________

param(
[parameter(valueFromPipeline=$true, position=0)]
	[string]$str
)
Begin{}
Process{
Write-Host -ForegroundColor Yellow $str
}
End{}

TO JEST PRZETWARZANIE POTOKOWE


SKRYPT do tworzenia nowego użytkownika w AD

<#
.SYNOPSIS
Simple script simplifying LoginUnion User Creation obligatory information: department, title, surname and given name
While choosing two-part department name you need to manually add quotes e.g. projects -> “new projects”
.EXAMPLE
./newComputerUser.ps1 -surname Nazwisko -givenName Imię -title testowy -department “ongoing projects” -mobilephone “+ 66 666 66 66”
Password generated: M04?8\_r
Password copied to clipboard
.NOTES
Author: nexor
Version: 01.04.2016
- 04.01.2016 readkey method changed to handle remote sessions
- 10.12.15 - read from excel 
- 10.08.2015 - email alert and groups 
- 10.07.15 - addded creation of hosting user
#> 

[cmdletbinding(DefaultParameterSetName=“Excel”)]
param(
	[parameter(ParameterSetName=“Excel”, position=0, mandatory=$true)][string]$fileName,
	#excel file name to be imported. Read full help for details about excel file
	[parameter(ParameterSetName=“input”, mandatory=“true”)][alias(“sn”)][string]$surName,
	[parameter(ParameterSetName=“input”, mandatory=“true”)][alias(“gn”)][string]$givenName,
	[parameter(ParameterSetName=“input”, mandatory=“true”)][string]$title,
	[parameter(ParameterSetName=“input”, mandatory=“true”)][ValidateSet(“Sales”, “NewProjects”, “ongoing projects”, “IT”, “Board”, “Office”, “Marketing”, “Accounting”)][string]$department,
	#department is importantas distribution groups are based on it… and not only. Must be one of validated names 
	[parameter(ParameterSetName=“input”)][string]$EmailAddress,
	#if not provided - generated automatically as givenname.surname@logicunion.pl
	[parameter(ParameterSetName=“input”)][string]$AccountPassword,
	#if not provided - generated automatically randomly and shown on the screen
	[parameter(ParameterSetName=“input”)][string]$mobilePhone,
	# users mobile phone
	[parameter(ParameterSetName=“input”)][string]$company=‘LogicUnion’,
	# company name - put your name here
	[PSCredential]$credential
	# if you connect remotely/user with lower privileges use credential to provide administrative access
)

Function new-RandomPassword{
	param(
		[int]$length=8,
		[bool]$Complex=$true
		#currently unused…
	)
	function GenerateSet{
		param(
			[int]$length,
			# number of ‘sets of sets’
			[int]$setSize,
			# number of available sets to drawn
			[int]$Complexity=3
			# minimum number of different sets in set of sets
		)
	$safe = 0
	While ($safe++ -lt 100) {
		$array=@()
		1..$length|% {
			$array+=(get-random -maximum ($setsize) -minimum 0)
		}
		if (($array|sort-object -unique |Measure-object).count -ge $complexity) {
			return $array
		} else {
			Write-Verbose “[generate-Set]bad array: $($array -join ‘,’)”
		}
	}
	return $null
}
# prepare char-sets
$smallLetters=$null
97..122|%{$smallLetters+=,[char][byte]$_}
$capitalLetters=$null
65..90|%{$capitalLetters+=,[char][byte]$_}
$numbers=$null
48..57|%{$numbers+=,[char][byte]$_}
$specialCharacter=$null
58..64|%{$specialCharacter+=,[char][byte]$_}
91..96|%{$specialCharacter+=,[char][byte]$_}
$ascii=@()
$ascii+=,$smallLetters
$ascii+=,$capitalLetters
$ascii+=,$numbers
$ascii+=,$specialCharacter
# prepare set of character-sets ensuring thath there will be at least one character from at least 3 different sets 
$passwordSet=generate-Set -length $length -setSize $ascii.length

$password=$null
0..($length-1)|% {
	$password+=($ascii[$passwordSet[$_]] | Get-Random)
}
Return $password
}

Function Remove-Diacritics {
param([String]$src= [String]::Empty)
	$normalized=$src.Normalize([Text.NormalizationForm]::FormD)
	$sb = new-object Text.StringBuilder
	$normalized.ToCharArray() | % {
		if ($_ -eq ‘ł’) {$_=‘l’}
		if ( [Globalization.CharUnicodeInfo]::GetUnicodeCategory($_) -ne [Globalization.UnicodeCategory]::NonSpacingMark) {
			[void]$sb.Append($_)
		}
	}
	$sb.ToString()
}

# READ USER DATA FROM EXCEL
if($fileName) {
	Add-Type - Path “$($PSScriptRoot)\EPPlus.dll”
	if (!($fileName = (Resolve-Path $fileName).Path)) {
		return
	}
	Write-Debug “target excel file $filename”

	$stream = new-object -typename System.IO.FileStream - ArgumentList  $filename, “Open”, “read”
	$xl= new-object -typename OfficeOpenXml.ExcelPackage -ArgumentList $stream

	$worksheet=$xl.Workbook.Worksheets[1]
	$givenName= $worksheet.Cells[2,2].Value
	$surname= $worksheet.Cells[3,2].Value
	$company= $worksheet.Cells[4,2].Value
	$department= $worksheet.Cells[5,2].Value
	$title= $worksheet.Cells[6,2].Value
	$mobilePhone= $worksheet.Cells[7,2].Value

	# close file
	$stream.close()
	$stream.dispose()
	$xl.dispose()
	$xl =$null
}

$newUser = @{
	company=‘LogicUnion’
	path=“OU=LogicUnion,DC=wfiles,DC=lab”
	officePhone=“+48 (22) 232 23 23”
	enabled=$true
	Department=$department
	Title=$title
	Surname=$surname
	givenName=$givenname
}

$SamAccountName=remove-Diacritics $([string]($givenName.Substring(0,2)+$surname.Substring(0,4)).ToLower())
$upnSuffix=“@logicunion.pl”
$displayName=“$givenname $surname”
$UserPrincipalName=“$SamAccountName$upnSuffix”

If(-not $AccountPassword) { $AccountPassword=new-RandomPassword }
Write-Host “password generated: $AccountPassword”
$AccountPassword | clip
Write-Host “password copied to clipboard”
if(-not $EmailAddress ) { $emailaddress=[string](”$(Remove-Diacritics ($displayName -replace ‘ ‘,’.’))$upnSuffix).ToLower() }
$proxyAddresses=@(“SMTP:$EmailAddress”,(“smtp:$SamAccountName$upnSuffix”))
if($mobilePhone) {$newUser.add(‘mobilePhone’,$mobilePhone)}
$OtherAttributes=@{‘proxy addresses’=$proxyAddresses}
if($credential) {newUser.add(‘credential’,$credential)}

$newUser.Add(‘SamAccountName’,$samAccountName)
$newUser.Add(‘displayname’,$displayName)
$newUser.Add(‘name’,$displayName)
$newUser.Add(‘UserPrincipalName’,$UserPrincipalName)
$newUser.Add(‘AccountPassword’,(ConvertTo-SecureString -String $accountPassword -AsPlainText - Force))
$newUser.Add(‘EmailAddress’,$emailAddress)
$newUser.Add(‘OtherAttributes’,$otherAttributes)

Try {
	New-ADUser @newUser
} catch {
	write-error “nie udało się założyć usera:  $_”
	exit (-1)
}

$group=@{
	members =$SamAccountName
}
If ($credential) {$group.add(‘credential’, $credential) }
Add-ADGroupMember -Identity ‘all’ @group
# Add-ADGroupMember -Identity $($newuser.item(‘department’)) @group

$body=“wiadomość wygenerowana przez skrypt zakładający użytkownika`
	imię i nazwisko: $($newUser.Item(‘givenname’)) $($newUser.Item(‘surname’))`
	login: $($newUser.Item(‘SamAccountName’))`
	hasło: $accountPassword “
# send-MailMessage -Subject “NOWY UZYTKOWNIK” -From “servicedesk@logicunion.pl” -SmtpServer <IP.ADD.RE.SS> -To “servicedesk@logicunion.pl” -Body $body -Encoding UTF8

Write-Host “done. Pozostaje czekać na synchronizacje z o365 (do 3h) i przypisać licencje.”


_________

MODUŁ 4 - wymuszanie wartości Switch, HelpMessage vs Command Based Help, Zakres działania zmiennych 


Function new-obj {
 [cmdletbinding(DefaultParameterSetName=‘user’)]
param(
	#ten parametr opisuje wciąganie pliku do skryptu
	[ValidatePattern(“^.*\.(txt|csv)$”)]
		[string]$filename,
		[switch]$force,
	#ten parametr opisuje nazwę użytkownika 
	[Parameter(mandatory=$true,ParameterSetName=‘user’,position=0,valueFromPieplineByPropertyName= $true)]
		[string]$userName,
	#ten parametr opisuje wiek użytkownika
	[Parameter(ParameterSetName=‘user’,position=1,valueFromPieplineByPropertyName= $true)]
		[ValidateRange(18,120)]
		[int]$wiek,
	#wiek użytkownika 
	[Parameter(ParameterSetName=‘user’,position=2, valueFromPieplineByPropertyName= $true)]
		[ValidateSet(“K”, “M”)]
		[string]$plec,
	#komputer
	[Parameter(mandatory=$true,ParameterSetName=‘computer’,position=0, valueFromPieplineByPropertyName= $true)]
		[string]$computerName
	#system operacyjny
	[Parameter(ParameterSetName=‘computer’,position=1, valueFromPieplineByPropertyName= $true)]
		[string]$platforma
)
Write-host “zczytujemy plik: $filename“
Write-host “nasz force: $force”
switch($PSCmdlet.ParameterSetName) {
	‘computer’ {
		write-host -foregroundcolor Red $computerName
		write-host -foregroundcolor Cyan $platforma
	}
	‘user’ {
		write-host -foregroundcolor Yellow $userName
		write-host -foregroundcolor Cyan $wiek
		write-host -foregroundcolor DarkMagenta $plec
	}
}
}

$confirmPreference -> w systemie domyślnie LOW

Get-process -name *edge |stop-process -confirm:$false
Pierwszy przypadek negowania

Message-help to pozostalosc po PS 1.0, nieużywany kompletnie

Skrypt

Function fun {
	$abc=‘funkcja’
	Write-host “fun: $($script:abc)” #$global also
}

$abc=“skrypt”
Write-host “skrypt: $abc”
fun


________
about_scopes -> help, wieecej o global, script

Echo (get-variable -name abc -scope 0 or 1 or 2) zagniezczone funkcje i odwolania do nich
