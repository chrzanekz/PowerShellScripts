Powershell dla początkujących

Get-Alias - wyświetla skróty do komend Powershella
Get-History
Get-Help
R 104 - powoduje wywołanie polecenia z historii konsoli (Invoke-History) + numer polecenia z historii
Verb-noun - czasownik-rzeczownik - podstawowa składnia w powershellu
Set-location
Get-command
Get-module
Get-childitem
Import-Module $nazwamodułu - od powershenla 3.0 nie jest już to niezbędne 
Get-netipconfiguration - zamiennik ipconfig
Test-connection - zamiennik pinga
Get-module -listavailable

Powershell providers
Get-PSProvider - wylistuje providery wykorzystywane w powershellu
Cd HKCU 	- wejście do rejestru current user
.\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\ - rzeczy które są uruchamiane przy logowaniu danego usera 

Get-itemProperty - właściwości danego obiektu, jeśli w rejestrze to danego klucza 

New-Item abc - tworzy nowy klucz “abc”

Cd env: - przechodzimy do zmiennych środowiskowych, które możemy później wylistować :D
$env.temp - wylistuje nam lokalizacje zmiennej środowiskowej o nazwie TEMP

Help - pomoc do pomocy :D

Get-help get-process
Nawiasy kwadratowe [] - oznacza ze coś nie jest obowiązkowe, ale jest opcjonalne :D
Kazda komenda posiada kilka wariancji do wykorzystania :D wiesz w helpie

Update-help
Help *process*

Get-help get-process -showwindow -> help pokazuje się w osobnym okienku
Mamy tam finda, który pozwala nam znaleźć pewne funkcje

Get-help - {ctrl + spacja}
Pozwala nam wyświetlić wszystkie możliwe parametry do danej komendy -> dostępne od PowerShell 5.0

Get-help -Full
- Examples Get-Process

Get-help About* -> artykuły na temat wykorzystania danego narzędzia/ komendy

Help about_aliases -> cały art , ogromna ilość wpisów

Get-help get-service -online -> przenosi nas na stronę technet Microsoftu

Kill 804 -> alias stop-process 804 -> zabija proces

Get-EventLog -> pobieranie informacji z systemowego logu

Man Get-Eventlog 

Get-eventlog -newest 10

Eventwvr w ctrl+r = otworzy event viewera i możemy znaleźć sobie logi systemowe

Tabulator podpowiada przy okazji parametrów 

Get-ChildItem *.msc -Recurse (wgłąb folderu) - Force (wymusza) -File (tylko pliki) -ErrorAction (reakcja na błąd) SilentlyContinue (wyciszanie błędów)

Services.msc

Get-help Get-EventLog
<> -> oznczenie tego typu oznacza, że będzie potrzebny <string[]> albo <int64[]>
[] -> oznacza tablicę

$tablica =1,2,3,’a’

$tablica[2]

Get-help remove-item 

<string[]>

Del (listuj tutaj elementy)

Get-event log -Computername server01, server02, server03 -Newest 5
Value for LogName

Nazwy parametrów również mają aliasy

Ls *.msc -recurse -erroraction silentlycontinue

-erroraction -> -ea (ALIAS)

Rozróżnienie między nawiasami [({

[ -> elementy tablicy
( -> przetworzony będzie blok i podany wynik coś jak nawiasy w matmie (2+2)
{ -> script block, można pisać kilka liniii jednocześnie


PowerShell jest obiektowy
Pipelining
Składnia
Pełen framework .NET pod spodem, nieograniczone możliwości
Ułatwienia w Powershellu -> Tab completion, luźna składnia, wiele skrótów, aliasów, elastyczność

OBIEKT
- Properties (właściwości)
    - Nazwa: młotek
    - Masa: 1,5kg
    - Rękojeść: narzędzia.młotki.trzony
    - Obuch: narzędzia.mlotki.obuchy
- Metody
    - Wbij (co [typ])

$host.ui.background

Mozna zmieniać wartości w tych obiektach, podejrzewam, ze jest sporo takich obiektów które można modyfikować

PIPE & pipelining
Znak |

$host | get-member

TypeName -> oznacza jakiego typu jest to obiekt, do jakiej grupy należy

MemberType -> oznacza jakiego typu obiekt to jest np. Metoda albo Property czyli własność itd.

Definition -> jakie dane przyjmuje dana metoda, właściwość itd.

$host.ui.writeerrorline(“abc”) -> wyrzucenie błędu z tego obiektu

Jak sprawdzić co to za obiekt? Get-member
Format-custom 

$host | format-custom | out-host -paging

Ciekawostka: skąd wiemy ze $host istnieje?
Ls variable: -> wylistowuje wszystkie zmienne w systemie -> wykorzystuje Powershell providers

Get-psprovider -> pokazuje elementy składowe powershenla

$PSHOME, gdzie jest zainstalowany pwoershell w systemie

Get-help about_automatic_variables -ShowWindow
Opisuje o zmiennych które przechowują informacje o powershellu (tworzone i zarządzane przez PS)

Get-help about_preference_variables

Variables that customize the behavior of PowerShell 

Niektóre polecenia zwracają obiekty różnych typów 

DALSZE TEMATY DO NAUKI

Zaawansowana składnia

Integrated Scripting Environment (ISE)

WMI I CIM

Funkcje/skrypty

Moduły 

Profile

Remoting 

DSC - Desire State Configuration


————

MODUŁ I

Ls
Get-ChildItem
Alias dir
Alias ls
Stare parametry nie działają

Get-Verb -> pokazuje określone czasowniki, do których ogranicza się PowerShell 
Są one też pogrupowane na poszczególne czynności -> Common, Data, Lifecycle etc.

Ls | get-member

Pozwala nam określić jakiego typu jest dany obiekt oraz pozwala sprawdzić jakie metody może użyć dany obiekt

LS -> przykładowo posiada dwa typy: DirectoryInfo oraz FileInfo, ponieważ odnosi się do plików oraz folderów

Ls | select name -> pozwala tylko wyświetlić jeden atrybut

Ls | select *name*, *path* -> przetwarza I pokazuje całkowicie inne formatowanie, ale pozwala też wybrać więcej atrybutów, dostępne są wildcardy

Powershell posiada odpowiednich providerów i zawiera strukturę hierarchiczną, np. PSPath zawiera na początku Microsoft.Powershell.Core\FileSystem, który jest odpowiednim obiektem konkretnego providera

Cd hklm:/ -> przejście do kluczy

Ps1xml -> rozszerzenie które opisuje poszczególne domyślne komendy takie jak np. Get-service i podaje nam domyślnie trzy typy wartości i wyświetla je w formie kolumny

Wyszukiwanie ścieżki do procesu:
1. Get-Process | get-member
2. Get-Process -Name *powershell*
3. Get-Process -name PowerShell | select path
4. Get-process | where-object ProcessName -eq PowerShell
5. Get-process | where-object ProcessName -match ‘PowerShell’ | select processname, path
6. (Get-process | where-object ProcessName -match ‘PowerShell’).path

Get-ChildItem -Recurse -Filter *.ps1xml | select *name

Wylistuje nam wszystkie dostępne pliki zawierace informacje na temat każdego obiektu

Notepad <sciezka do pliku>
W przypadku plików .ps1xml pokazuje nam plik xml w którym jest utworzona hierarchia plikowa, bardzo łatwo wyczytać strukturę całego pliku

Przypomnienie+

Notacja nazewnicza
- Get-childitem vs dir vs ls
- Get-verb

Obiektowosc 
- Get-member

Filtrowanie (sito)
- Select-object 
- Różnica pomiędzy select-object, a select-string
    - A co to jest samo “select”?
- Where vs -filter

Alias select -> select-object

Ls | select-string -Pattern “ps1” -> znajduje wśród plików określone stringi, podaje linie danego pliku oraz zawartość tej linii w danym pliku :D

Select-String -Pattern “ps1” -path *.ps1

Select-String -Pattern ‘regex’ -path *.ps1 -context 2 

netstat -> pozwala pokazać nam otwarte porty, ktore sa uzywane do polaczen :D

netstat /anb -> pokazuje jakie procesy aktualnie wykorzystują jakie procesy

netstat /anb | select-string -pattern 443 -> pokaze nam polaczenia szyfrowane aktywne na kompie

netstat /anb | select-string -pattern 443 -context 1 -> pokaze nam procesy ktore sa uruchomione na porcie 443

alias where -> ?

Wbudowane narzedzia filtracyjne takie jak Where-Object daja lepsze rezultaty wydajnosciowe niz kolejne pipeowanie nastepnych polecen

Najlepiej jak polecenie posiada swoj wewnetrzy filtr, wtedy skraca to bezposrednio od razu wykonywanie zadan

for ($i=0; $i -lt 10; $i++) {echo $i} -> loop od 0 do 9

get-process | foreach-object{ echo $_.name} -> wyswietli nazwy wszystkich procesów

4..10|%{Test-Connection 192.168.8.$_ -Count 1} -> pingowanie maszyn z zakresu 192.168.8.4-10, swietny skrypt

Get-NetIPConfiguration

New-ADUser 'test' -Server <adres_ip servera> -Credential (Get-Credential)

mstsc /v <adres ip kompa do ktorego chcemy sie zalogowac>

ustawianie zmiennych przed wykonaniem skryptu
$dc='172.168.0.4'
$cred=get-credential
wpisujemy credentiale
1..100|$ {new-aduser -server $dc -credential $cred "user$_"}

prawdopodobnie w domenie bez uwierzytelniania taki proces zająłby duzo szybciej

foreach-object -> %
foreach i for to nie jest to samo!

$this -> $_

Active Directory -> uwaga na właściwości obiektu

where-object -> ?
zapis pełny i skrócony

Get-Module
Get-Command -Module DnsClient

Get-ADComupter -Server "adresIP domenowego servera" -credential get-credential -Filter *

Get-ADComupter -Server "adresIP domenowego servera" -credential get-credential -Filter * | gm
chciałbym przejrzeć jakie komputery jakie mają systemy, dlatego biorę get-member, zeby spojrzec jakie parametry moge wypiepować

Get-ADComupter -Server "adresIP domenowego servera" -credential get-credential -Properties *
komputery z AD zeby zachowac wydajnosc nie pobieraja wszystkich informacji z domeny dlatego tez ciezko nawet nam w Get-Member znaleźć tego typu informacje :/

Get-ADComupter -Server "adresIP domenowego servera" -credential get-credential -filter * -properties * | gm
w tym momencie zostaną nam wylistowane wszystkie niezbędne informacje, ktore mozemy pobrac bezposrednio z maszyny z domeny

Get-ADComupter -Server "adresIP domenowego servera" -credential get-credential -filter * -properties * | select name,OperatingSystem*
wyswietli nam wszystkie kompy z domeny oraz pokaze nam jakie systemy operacyjne uzywaja, service packi, hot fixy itd.


Get-ADComupter -Server "adresIP domenowego servera" -credential get-credential -filter * -properties * | where OperatingSystem -match '2008'

Get-ADComupter -Server $dc -credential $cred -filter * -properties operatingsystem | where-object { $_.OperatingSystem -match '2008'} | select name,operatingsystem

klasyczna metoda odpytania tej informacji POROWNAJ Z TA WYZEJ

Zaawansowane filtrowanie:
- select-object (własne nazwy kolumn oraz obliczenia)
- matematyka
- zmienna $_ -> $this
- hashtable @{}

ls | select * | Out-Host -Paging

ls -File | select name, length | sort length
1MB - pokazuje wielkosc jednego MB

 (1MB-1KB)/1KB -> wyswietli nam informacje w KiloBajtach

$ht=@{ } -> tablica hashowana
$array=@( ) -> zwykła tablica

$array=(1,2,'adasdad',(Get-Process)) -> przypisanie wartości do tablicy
  13 $array=(1,2,'adasdad',(Get-Process))
  14 $array
  15 history
  16 r14
  17 $array
  18 history
  19 $array[1] -> odwołanie do tablicy

$ht.Add("klucz2","wartosc2")
$ht.klucz -> wyswietli zawartosc podanego klucza

 ls -Filter d* | select name, @{name='wielkosc';expression={$_.length/1KB}}

filtruje nazwy plikow zaczynajace sie od d oraz podaje nam nazwe pliku oraz jego wielkosc w kilobajtach, dlatego uzylismy expression (matematyka)

ls -Filter d* | select name, @{name='wielkosc';expression={"{0:N2}" -f ($_.length/1KB)}}  | sort wielkosc

uzylismy nowego obiektu, ktory stworzylismy w opcji "expression" i jesli chcemy posortowac wyniki musimy sie do niego odniesc -> mozemy to sprwadzic jak zwykle poleceniem Get-Member

skrocony zapis w tablicy hashujacej -> @{l='wielkosc'; e={$_.length/1KB}} -> L i E

 Get-Command -Verb convertto, export

podaje nam komendy convert to oraz export

get-service | ConvertTo-Html | Out-File c:\serwisy.html -> exportuje nam wyniki komendy do tabeli zawartej w kodzie html 

get-service |? status -match 'run' | select name, DisplayName, Status | ConvertTo-Html | Out-File C:\temp\uslugi.html
Wyswietla serwisy ktore pracuja bezposrednio do pliku html

get-help ConvertTo-Html -ShowWindow
Syntax
    ConvertTo-Html [[-Property] <System.Object[]>] [[-Head] <System.String[]>] [[-Title] <System.String>] [[-Body] <System.String[]>] [-As <System.String>] [-CssUri <System.Uri>] [-InputObject <System.Management.Automation.PSObject>] [-PostContent <System.String[]>] [-PreContent <System.String[]>] [<CommonParameters>]

    ConvertTo-Html [[-Property] <System.Object[]>] [-As <System.String>] [-Fragment ] [-InputObject <System.Management.Automation.PSObject>] [-PostContent <System.String[]>] [-PreContent <System.String[]>] [<CommonParameters>]


get-service | ? Status -Match "run" | ConvertTo-Html -Property name,displayname,status -title "raport uslug" -PreContent "uslugi dzialajace na komputerze $($env:COMPUTERNAME)" -PostContent "wygenerowano $(Get-Date)" | Out-File C:\temp\uslugi.html

generuje raport z zmodyfikowanmi nagłówkami oraz data wygenerowania, warto zawsze popatrzec w opcje -OutWindow oraz Get-Member

PS C:\Windows\system32> Get-Service | Export-Csv c:\temp\uslugi.csv
PS C:\Windows\system32> C:\temp\uslugi.csv
Excel nie ogarnia plików wygenerowanych w ten sposób

Get-Service | select name,displayname, status|  Export-Csv c:\temp\uslugi.csv -Delimiter ";" -NoTypeInformation
Średnik oddzielający kolumny i wiersze, oraz NoTypeInformation, ktory nie bedzie brac gornego wiersza

Konwersja wyników 
export-csv
convertto-html
convertto-json
convertto-xml

Przekierowanie wyjścia
C:\Windows\system32> get-command -Verb out

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Out-Default                                        3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Out-File                                           3.1.0.0    Microsoft.PowerShell.Utility
Cmdlet          Out-GridView                                       3.1.0.0    Microsoft.PowerShell.Utility
Cmdlet          Out-Host                                           3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Out-Null                                           3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Out-Printer                                        3.1.0.0    Microsoft.PowerShell.Utility
Cmdlet          Out-String                                         3.1.0.0    Microsoft.PowerShell.Utility

Get-Process|Out-GridView
swietnie to wyglada okienko
szybciej czasami mozna cos znaleźć w GUI

$file=ls C:\temp|Out-GridView -PassThru
Passthru oznacza, ze dane wpadną i wypadną i otworzy sie to co jest w danym folderze, zajebista opcja

$dc="adresIP"
$cred=get-credential
Enter-PSSession -ComputerName $dc -Credential $cred
hostname

echo "adjiajdaid" > c:\temp\plik.txt

Przekierowanie błędów do plików oraz logów

Wyświetlanie wyników:
- out-gridview
- format-*
get-command -Verb format

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Function        Format-Hex                                         3.1.0.0    Microsoft.PowerShell.Utility
Function        Format-Volume                                      2.0.0.0    Storage (NIE UZYWACXD)
Cmdlet          Format-Custom                                      3.1.0.0    Microsoft.PowerShell.Utility
Cmdlet          Format-List                                        3.1.0.0    Microsoft.PowerShell.Utility
Cmdlet          Format-SecureBootUEFI                              2.0.0.0    SecureBoot
Cmdlet          Format-Table                                       3.1.0.0    Microsoft.PowerShell.Utility
Cmdlet          Format-Wide                                        3.1.0.0    Microsoft.PowerShell.Utility


ls | format-list
ls | format-table
ls | format-wide
ls | select * | Format-Wide -Column 3 -> pokzuje 3 kolumny

Get-Item .\uslugi.csv | Format-Custom
Pokazuje jakoś inaczej te dane przedstawione w klasach :D

*-ADUser
Mechanizm działania '|'
Import/export uzytkownikow

man New-ADUser -ShowWindow

New-AdUser "user01" -AccountPassword "P@ssw0rd"
Get-Command -Verb convertto

man ConvertTo-SecureString -ShowWindow
Converto-SecureString -String "P@ssw0rd"
Te powyższe nie działają

ConvertTo-SecureString -String "P@ssw0rd" -AsPlainText -Force -> zadziała to wymuszone :D

New-ADUser "user01" -AccountPassword(ConvertTo-SecureString -String "P@ssw0rd" -AsPlainText -Force) -Server $dc -Credential $cred -Enabled $true
Dodawanie uzytkownika z poziomu konsoli

New-ADUser -AccountPassword(ConvertTo-SecureString -String "P@ssw0rd" -AsPlainText -Force) -Server $dc -Credential $cred -Enabled $true - Name "uzytkownik3" -Company "LogicUnion" -City Warsaw -Country PL -Department Board -DisplayName "nowyuser3" -emailaddress 'user@gmail.com' -GivenName 'imie' -Surname 'naziwsko' -Path "ou=logicunion,dc=wfiles,dc=lab"

Pliki, ktore chcemy uzyc do importu do skryptu powinny byc zazwyczaj w pliku .CSV, wtedy mozna nimi manipulowac za pomoca skryptu (oddzielone sa srednikami).

$users=import-csv ./plik.csv -> import pliku CSV
$users.count -> liczba rekordów

$users -> źle to wyglada
$users=import-csv ./plik.csv -Delimiter ';' -Encoding Default (pomaga rozwiązać problem z czcionkami polskimi)

$users | skip 15

ASCII, Default, Unicode, UTF7, UTF8, UTF32, OEM, BigEndianUnicode

H | ? Commandline -match ‘aduser’ | select -expandproperty commandline

$users | % {New-ADUser -AccountPassword (ConvertTo-SecureString -String “Password” -AsPlainText -Force) -Server $dc -Credential $cred -Enabled $true -Name $_.name -Company $_.company -Country $_.country -Department $_.department} 
Wrzucanie użytkowników z odpowiednio przygotowanego pliku XLS do kontrolera domeny

Get-process | ? processname -match ‘edge’ -> znajduje procesy Edge MS
Get-process | ? processname -match ‘edge’  | kill

Man get-process -full

Man stop-process -parameter inputobject

Najprostszy sposób na stworzenie własnego obiektu
$obj= “” | select name
$obj.name = ‘microsoftedge’
$obj | stop-process -> pozwoli po tej serii komend skillować podany process

$users | % {$_ | NewADUser -AccountPassword  (ConvertTo-SecureString -String “Password” -AsPlainText -Force) -Server $dc -Credential $cred -Enabled $true} 

MODUŁ 4 - AD, WMI, CIM i inne

Get-ADComputer
WMI/CIM
Moduł Active Directory
Cache AD
Języki w języku 
Różnicę w wersjach WMF

4..7 | {Test-Connection 172.21.0.$_ -Count 1}

$dc

Get-ADComputer -Identity labad  -credential $cred -Server $dc
Pobranie informacji o komputerze zdanie z domeny AD

$params=@{credential=$cred;server=$dc}
$params.server 
Get-ADComputer -Identity labad @params
Przekazanie danych credential oraz server w tablicy hashującej

Get-ADComputer -Identity labad -Properties * @params | gm
Cache nie pokazuje wszystkiego, można inna komenda wywołać wszystkie properties 

Get-ADComputer -Identity “server*” @params -> nie zadziała
Get-help get-adcomputer -full

Get-ADComputer -Filter * @params
Na początek zobaczymy czy działa, i wyświetla wszystkie maszyny :D

Get-ADComputer - Filter “server*” @params -> nie zadziała, operator not supported
Get-help get-adcomputer -Parameter Filter | out-host paging
Null nie jest Wildcardem

Get-ADComputer @params -Filter {name -match “server”}
Nadal nie działa
Filter don’t support this kind of operator compare “match”

Get-ADComputer @params -Filter {name -like “server”} -> nadal nie da dobrego wyniku

Get-ADComputer @params -Filter {name -like “server*”} -> operator like wymaga podania jakiegoś znaku typu wildcard

WMI

Man get-wmiobject -parameter filter 
Help pokazuje ze musimy podać składnie filtra w języku WQL WMI Query Language

Get-ADComputer -LDAPFilter “(name=*laptop*)” -SearchBase “CN=Computers,DC=Fabricam,DC=com”
Składnia zapytań Filtra LDAP

Get-WMIObject -Class win32_operatingsystem -computername server01, server02, server03 -credential $cred
Pobierze informacje o systemie operacyjnym wielu komputerów

(Get-WmiObject Win32_OperatingSystem).caption.split()[4..5] 

Get-WMIObject -Class win32_bios-computername server01, server02, server03 -credential $cred
Pobierze informacje o bios wielu komputerów

Gwmi win32_bios -> skrót w lokalnym komputerze 

Get-WMIObject -Class win32_bios-computername server01, server02, server03 -credential $cred | convertto-html |out-file c:\temp\file.html
Przykładowy krotki raport w html 

CIM został wprowadzony w windows 2012

Selectami można pare rzeczy wyfiltrowac w tym raporcie albo tez dodać pare nowych informacji 

Enter-PSSession $dc -Credential $cred
Hostname
Za pomocą WinRM zarządzanie komputerami (PSSession)
[zdalnie] gwmi win32_bios -ComputerName server01
NIe zadziała, bo zdalnie nie będzie przekazywać parametrów, nie można korzystać z ścieżek sieciowych itd.
Zdalnie na komputerze nie można wykonywać operacji na innych komputerach :D

Multihoping jest mozliwy

Get-wmiobject win32_operatingsystem | fl
WMF 5.0 pozwala na łączenie się CIM’em do maszyn

Get-Module -listavailable
Nie ma modułu AD
Install-WindowsFeature -> tez nie działa w 2008r2 
Import-Module ServerManager 
Get-Command -Module ServerManager 

Get-WindowsFeature |? DisplayName -match “active” -> nie działa w 2008r2, 2.0 PowerShell

Get-WindowsFeature |? {$_.DisplayName -match “active”} -> dopiero zadziała w 2.0 PowerShell

Add-WindowsFeature RSAT-AD-Powershell -> instalacja AD PowerShell 

Różne wersje Powershella potrzebują różnych komend, trzeba zawsze skrypty dostosowywać pod najniższa wersje. Zawsze można tez upgradeowac do najnowszej wersji WMF’a.

Get-CIMSession
Get-command -module cimcmdlets -> pokaże cmdlety dla CIM

Get-help new-cimsession

New-CIMSession -ComputerName <adres_ip> -Credential $cred 

Get-CimSession -> pokazuje aktywne sesje z maszynami 
Protokół WSMan 

Get-CimClass | out-host -paging
b.duzo klas

Get-cimsession | get-ciminstance -classname win32_diskpartition | convertto-html | out-file c:\temp\file.html
Pokaże informacje o partycjach z wszystkich komputerów w domenie z którymi mamy sesje utworzona 

Cim tworzy sesje i nie potrzebuje za każdym razem się uwierzytelniać przy odpytaniach jak to robi WMI, dlatego CIM jest dużo szybsza metoda odpytywania maszyn :D

Dalsze tematy do nauki 

Remoting +
WMI i CIM +
Integrated Scripting Environment ISE
Profile 
Funkcje Skrypty
Własne moduły
Desire State Configuration
