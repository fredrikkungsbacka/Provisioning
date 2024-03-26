# Changelog
All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog(https://keepachangelog.com/sv/1.1.0/), and this project adheres to Calendar Versioning(https://calver.org/).

<details>

<summary> Template </summary>

## Version

### Added
- New features

### Changed
- Changed behaviour

### Fixed
- Fixed bugs

### Caveat
- Things to take note off

### Security
- Security related fixes and changes

### Removed
- Removed features

</details>

## Unreleased
- Inget just nu

## 2024.4.1
### Removed
- Tillfälliga alternativ 99 tas bort

## 2024.3.3
### Removed
- Tar bort stöd för SecureCRT 9.4
### Changed
- Använder numera en del av LM-nummer i hostnamnet istället för hela
### Fixed
- Lagat sönder en sökväg vid skapandet av CSR

## 2024.3.2
### Fixed
- Vid addering för monitorering från alternativ 2 felade variabeltypen
### Added
- När man gör en trunk verifieras att det interfacet inte är anslutet
- Installerar modulen cryptography
- Utökad behörighetshantering
### Changed
- Timeout för WaitforString och ReadString har enats i hela scriptet
- Förbättringar när management-vlan detekteras
- Städat i listan över moduler som installeras, och gjort vissa beroende på gruppbehörighet
### Removed
- OpenSSL.crypto.PKCS12 är inte längre supporterad, slutar använda modulen pyOpenSSL

## 2024.3.1
### Added
- DHCP relay agent för extern accessport adderas nu vid behov
- Dialog för ipadress, adress och populärnamn för site
### Fixed
- Line send delay saknades för cmd
- WaitForString i samband med CMD hanterades felaktigt på grund av bug
- Felhantering från crt_box_dialogue var inkonsekvent
- WaitForStrings har en fördröjning när inte objektet crt används, vilket gjorde att matchning ofta missade
- Funktionen get_model kunde ibland matcha felaktigt på kommandot
- Delay i crt_sendline räknade fel om nästa kommando var en crt-funktion
### Changed
- Total omskrivning av excel_read_br för att kunna skriva om strängar med ovanliga tecken

## 2024.2.2
### Fixed
- Problem med referens till filnamn för byggnadsregistret i settings.json
- Payload felaktig vid discovery i Solarwinds på grund av felaktig placering av ny funktion

## 2024.2.1
### Added
- Stöd för SecureCRT 9.5
- Check_web_server har snabbats upp
- Uppslag i byggnadsregistret görs om
- Ny namnstandard för hostname
- När åldern på ett lösenord för ett AD-konto i Passbolt närmar sig 30 dagar innan tvingande byte, kommer användaren bli uppmanad en gång per dag tills det är bytt.
- Det går nu att lägga till endpoints utan att de tidigare har anslutit till nätverket
- Varning om en ny nod i Solarwinds finns i ignore list
- Ny funktion för backup av delade resurser i Passbolt
### Fixed
- Unpluggable sattes fel på accessportar (10-15)
- Användningen av User-Agent var inkonsekvent och delvis felaktig mot RFC
- Avslut av session vid fel mot Passbolt hanterades inte
- Utökad loggning vid borttagning från Solarwinds
- Slutade hantera serieportar när en ogiltig port påträffades
- PID och VID för Ciscos USB-adapter presenteras inte längre av Windows
### Changed
- "Remove node…" omdöpt till "Delete node…"
- Copyright borttagen då den inte krävs sedan år 2000

## 2023.10.2
### Added
- Stöd för RESTCONF
- Verifiering av användardata från Passbolt
### Fixed
- Loop när enhet läggs till för övervakning i DNA-Center
- Energywise på enheter utan support för det felar
- Rättat delar av koden för Passbolt efter designfilosofin
- Fel vid generering av csr
- Flera fel vid generering av pfx
- Efter byte av namn i alternativ fem, misslyckas inloggning då location inte blir korrekt satt
### Security
- Ökad säkerhet för NETCONF-YANG
- Ökad separation av användningen av variabeln secret

## 2023.10.1
### Added
- Tar bort backup av SecureCRT då den kräver en mer avancerad hantering än vad som är värt besväret
- Optimerat koden för integrationen med Passbolt
- Stöd för Catalyst 9300-24U
### Fixed
- Hade missat att lägga till Passbolt för alternativ 43
- Kunde få ett fel när install remove inactive är klar då raden klipptes när systemet väntade
- Source interface kunde inte sättas korrekt för ip http client
- Krasch när fel lösenord hämtades från Passbolt för Powershell
### Security
- Högre och konfigurerbar säkerhet vid användning av Powershell

## 2023.9.4
### Added
- Minskat exponeringen av inloggningsuppgifter mellan moduler
- Går nu att använda range för interfacekonfiguration
### Fixed
- Vissa tecken i lösenordet för en SSH-session får SecureCRT att stoppa scriptet
- Saknat undantag vid retry i requests
- Felstavning i alternativ 3 skapade en krasch

## 2023.9.3
### Fixed
- Missade installation av modulen pgpy
- sol_delete_node kunde krascha när nod tas bort i Solarwinds som redan är borttagen
- Fanns en risk att passphrase för Passbolt kunde sparas av misstag
- Autenticeringsfel i requests orsakade en krasch
- Fel lösenord i Passbolt orsakade en krasch
- Problem att skapa SSH-sessioner när lösenorden är för komplexa på grund av specialtecken

## 2023.9.2
### Added
- Rensat bort värden som baseras på grupptillhörighet
### Fixed
- Backup misslyckades då "Single Instance" inte kunde sättas

## 2023.9.1
### Added
- Istället för att hantera en krypterad fil med nycklar och lösenord, hämtas dessa numera i en integration med Passbolt
- Ges möjlighet att ansluta en trunkport när enhet läggs till för övervakning från alternativ 2
- Använder User istället för Device credentials i Solarwinds
- Enheter som läggs till för monitorering via provisionering, läggs till som unmanaged som standard
- Smartlicensiering direkt mot Cisco istället för egen satellit
- Förbättrad felhantering i requests
- Requests är nu mer robust vid tillfälliga kommunikationsproblem, och försöker flera gånger
### Fixed
- Lagt in en timeout ifall crt_connect_cmd inte kan detektera slutfört kommando
- Fastnade vid rensning av flash på IOS-XE
- Bug i SecureCRT kraschar applikation och/eller script efter en ny serie-session
- Fel i alternativ 14 där förslag inte gavs när trunkportar inte fanns
### Caveat
- En bug gör att script och/eller applikationen kraschar när man gör en unlock på alla tabar och sedan använder tab-objektet. Detta gör att det kommando som låste upp alla tabar måste tas bort. Innebär att om en tab är låst och scriptet talar med denna, kraschar scriptet med förklaringen att taben är låst.

## 2023.8.1
### Added
- Stöd för att lägga till KBN-enheter i övervakningen
- Ny och säkrare hantering av behörigheter
- Stöd för Python 3.11.
- Alla delar som använder requests delar nu en gemensam funktion för detta så att alla anrop får samma egenskaper
- I alternativ 2 detekteras om horizontal stack är aktivt, och avbryter om så är fallet
- Ny struktur för object och värden i sessioner
- Får nu en fråga efter provisionering ifall switchen skall adderas för monitorering
- Tar bort alternativ 99, tar plats och används inte
- Bättre felmeddelanden från funktionen check_web_server
### Fixed
- Ett fel i alternativ 3 som lämnade kvar en låst tab
- Städat ett par detaljer som bröt mot designfilosofin för scriptet
- Fel i crt_connect_cmd som gjorde att taben stängdes i förtid och loggen inte innehöll information
- Ett fel i alternativ 60 gjorde att det kraschade när man avbröt
- Detekterade inte huvudversion av Python korrekt
- Fel i alternativ 12 rörande eem script
- Hade missat detektering av os och plattform vid uppdatering av Python
- Nyckelfel vid nedladdning av uppdaterad nyckel
- Get_stack detekterar inte switchar där virtual stack måste aktiveras korrekt
### Removed
- Rar bort stöd för 3.9
- Slutar använda OrionSDK till fördel för den mer generella requests, då det är dåligt uppdaterat och saknar en hel del funktioner
- Tar bort stöd för SecureCRT version 9.3
### Changed
- Begränsa LLDP på trunkar och extern accessport. Detta kokar ned tabellen till enbart de enheter som syns på en lokal accessport

## 2023.5.1
### Added
- Integration med Cisco Firepower Management Center
- Bättre hantering av fel vid decodning av json-filer
- Utökad hantering av ogiltiga vlan när KBN-trunk skapas
### Fixed
- Ogiltiga namn i moduler för Solarwinds enligt pylint

## 2023.4.4
### Added
- Vid provisionering av ny enhet och ip eller namn redan existerar, tas vlan interface bort och hostnamn rensas
- Alternativ som skapar trunkar gav inget portexempel när switchen har en modul för trunkar
### Fixed
- Omdefiniering av inbyggd funktion (exit)
- Fick lära mig om deepcopy() för att fixa ett problem med att lägga in flera enheter i följd i ISE
### Changed
- Storm-control av multicast ökades till 20% på access-portar

## 2023.4.3
### Added
- Mall för nya enheter i ISE sätts nu i settings.json
- Nytt alternativ för att ansluta serieport med 115200 baud
### Fixed
- Har varit inkonsekvent med hur centrala variabler används av subfunktioner
- Beskrivning för portar som inte skall användas sattes inte i settings.json
- Funktionen put_personal_settings använde fel kodtabell
- Meny 20 hade fel ikon i dialogrutorna

## 2023.4.2
### Added
- Funktionen cisco_encrypt använder nu modulen hashlib istället för scrypt, som utgår
- Snabbat upp skrift till skärm genom att inte lässa sessions-config varje gång funktionen crt_sendline anropas
- Huvudet i menyn byggs nu helt dynamiskt då cli och gui har olika spacing för tecken
- Tagit bort dialog när session stänger eller kopplar ned
### Fixed
- Fel i verifiering av servrar i alternativ 3
- Cisco_encrypt visade sig formatera Cisco typ 8 och 9 nycklar felaktigt
### Removed
- Stöd för SecureCRT version 9.2 tas bort

## 2023.4.1
### Fixed
- Två fel från tidigare version rättade
- Fel i alternativ 40 gjorde att dialogen loopade när ett fel inträffade
- Funktionen för addering av vlan rensade inte skräptecken i listan
- Ett fel i uppgraderingsmodulen påverkade ISL-kompatibla enheter. Använder numera port_trunk för att skapa en trunkport
- Funktionen för namnbyte blev aldrig riktigt synlig när den lanserades. Fixade detta samt verifiering av nytt hostnamn i funktionen

## 2023.3.2
### Added
- Aktiverar DOM monitoring på modeller som stödjer detta
- Stöd för USB adaptrar från SiLabs
- Stöd för C9200CX
### Fixed
- Tar bort kontroll av confreg, då det värdet kan visas intermittent 
- 1000-switchar har en annan syntax för jumboframes
- I sol_update_custom fanns ett unikt värde som flyttades till settings
- Tagit bort stack-oid som separat värde, det är en effekt av stackwise
- Stöd för Netconf enbart för IOS-XE

## 2023.3.1
### Added
- Statusmeddelanden till cli för flera av kontrollfunktionerna
- Nätverksmoduler i switchar hämtas nu från models.json istället för i koden
### Fixed
- Fel i menyn i alternativ 20 åtgärdat
- Glömt att migrera snmp contact till settings.json
- SNMP contact fanns dubbelt
### Removed
- Tar bort stöd för Python 3.10 då en modul inte stödjer detta

## 2023.2.3
### Added
- Bättre felmeddelanden för seriesessioner

## 2023.2.2
### Added
- Lagt in ett tidigare separat verktyg
- Menyn för alternativ 20 byggs nu på samma sätt som huvudmenyn
- Funktioner för utfärdande och hantering av certifikat är nu tillagda
- Verifierar configuration register i alternativ 2 och 9
- Kan nu manuellt ange ip eller acceptera förvald adress i alternativ 2
- Tagit bort onödiga loopar, och likriktat användningen av get_model
### Fixed
- Fel vid uppgradering av IOS-XE skapade oändlig loop
- Återanvändning av öppna flikar med seriesessioner kunde fallera i vissa fall
- Kontroll av antalet serieportar skall bara kontrollera godkända adaptrar från listan
### Changed
- Reload sker nu sist i alternativ 2
### Security
- Mitigerar CVE-2023-20076

## 2023.2.1
### Added
- Uppgradering bryts ut som en funktion som kan återanvändas, detta minskar komplexiteten
- Menyn bryts ut som en funktion för att kunna återanvändas i andra script
- Felmeddelande om för många USB-adaptrar är anslutna (>1)
- Uppgradering tar inte längre bort aktiv image
- Gjort en del funktioner som hämtar in information mer robusta
- Hanterar felaktig USB-seriedrivrutin
### Fixed
- Krasch vid uppdatering av interface ifall Solarwinds inte är nåbar
- Fel vid prompt för överskrivning av befintlig fel kunde loopa uppgradering
- Felhantering av get_stack hade fallit bort
- "ip routing" finns inte på IE-3300
- Felhantering vid skapande av seriesession i alternativ 2 har fallit bort

## 2023.1.6
### Added
- Nytt alternativ som sparar aktiv session till Session Manager

## 2023.1.5
### Fixed
- Omsync till DNA-Center misslyckades då payload var felaktig
- KBN trunk kan inte använda ADD, så EEM-scriptet måste tas bort och lägga till
- EEM stöds inte av alla modeller

## 2023.1.4
### Added
- Varning när interface uppdateras på en enhet som inte är upplagd i Solarwinds, har nu tagits bort
- Nytt alternativ för att döpa om en enhet i alla system, och även på själva enheten via SSH
### Fixed
- Fann ett problem med detektering av viss text i en session, som gjorde skillnad på SSH och serie-sessioner. Detta innebär att samma fördröjning som serie-sessioner har för varje tecken, också läggs in i SSH- och Local Shell-sessioner.
### Changed
- Utökad loggning till buffert
- Slutar logga ntp
- Power budget för IE3300 var för låg

## 2023.1.3
### Added
- Alternativ två stänger inte länge av sessionen

## 2023.1.2
### Fixed
- (Connection timed out) vid uppgradering
- Tagit bort insamling av output vid Local Shell, detta gav intermittenta problem att avsluta session
### Changed
- Lagt till EEM-script vid provisionering som förhindrar vanliga misstag

## 2023.1.1
### Added
- Variablerna username och group sätts nu via systemenv
- Snabbat upp ssh och serie-sessioner
- Tar bort migreringar av inställningar från tidigare versioner
- Sätter diverse inställningar för emulering och färg för alla sessioner
### Fixed
- Input dialog saknade strip
- Fel i alternativ 13 som kraschade scriptet på switch med IOS-XE
- Ibland detekterades inte ett slutfört kommando i CMD

## 2.1.7
### Fixed
- Fel vid installation och uppdatering av moduler pga tecken från vissa moduler

## 2.1.6
### Fixed
- Optimerad laddning av externa moduler
### Removed
- Modulen python-certifi-win32 supporteras inte längre, byts ut mot pip-system-certs

## 2.1.5
### Fixed
- Hanteringen av serieportar kunde fela i alternativ 40
### Removed
- RDP-sessioner via script är från SecureCRT version 9.4 inte längre supporterat

## 2.1.4
### Added
- Restricted QoS på accessport försvinner
- Helt gjort om hur stackar hanteras samt rättat en del fel på vägen
- Lade till global metadata i docstring
- Multigig migreras in i accessport istället
### Fixed
- Ett fel smög sig in från förra versionen som rör identifiering av interface i kluster
- Ändrat användningen av begreppet cluster till stack, betyder olika saker

## 2.1.3
### Added
- Stöd för NETCONF
- Stöd för WS-C3560CX-12PD med multigig trunkportar
### Fixed
- Detektering om switch är ansluten i meny 2 kunde fela ibland
- Screen Sync kunde i vissa fall bli felaktig
- Funktionen get_model kunde krascha ibland av okänd anledning

## 2.1.2
### Added
- Uppdatering av moduler kan nu skjutas upp
- Verifiering om en switch är ansluten sker innan borttagning med val 4
- Flervalsfrågor har fått en ansiktslyftning
### Fixed
- Val 3 tog inte hänsyn till att description på port kunde ha olika strängar

## 2.1.1
### Added
- För en extern accessport görs nu även en shut/no shut
- Nytt alternativ för att rensa en port och markera som FREE
- Aktivera scriptindikator i tab
- Koden bakom menyn formaterar nu automatiskt kolumnerna och hämtar beskrivning från funktionerna
- Kommer att lansera i en publik version som saknar delar med sekretess
- "Description" på en port hämtar nu sitt värde från settings.json
- Stöd för utbyggnadsmodulen IEM-3300-8S
- Vid provisionering verifieras att ingen port är ansluten
### Fixed
- I meny 11 tas ordet ISE bort då det inte enbart kunde producera ISE-accessportar
- Smart license transport cslu var felstavat

## 2.10.3
### Added
- Sätter sessionsoptioner för RDP
- Hur menyn skapas är helt omskriven
- När en trunkport skapas (intern och mot kbn) görs nu en shut/no shut
- Alternativ 13, extern accessport, har fått validering av vlan id
- Json-fil för vlan innehåller nu mer information som används av olika delar
- Optimerat hur json-filer läses in
### Fixed
- När portkonfigurationer utförs (10-14) görs ingen unlock av tab när ett fel uppstår

## 2.10.2
### Added
- Möjlighet till gruppinställningar baserat på inloggad användare
- Verifiering av inloggad användare mot lista av godkända
### Fixed
- Strukturerat om personalsettings samt migrering
- Avslutar ssh sessioner felaktigt i rapporter och uppgradering när ett fel inträffar
- Single Instance blev fel vid uppstart
- Krash i rapport 32 om inga multigig-portar finns
- Auth prompt enbart giltigt i ssh-sessioner

## 2.10.1
### Added
- Backup av SecureCRT konfiguration varje månad
- Nödvändig katalogstruktur skapas om den saknas
- Nya menyalternativ för anslutning av SSH och RDP
### Fixed
- Tid som används i scriptet kunde skilja sig åt i olika delar
- Förbättrad och enhetlig detektering av värden i personalsettings
- Misstänker ett problem vid uppdatering av Python moduler när upplösningen på skärmen är dålig
### Changed
- Device classifier aktiveras nu som standard

## 2.9.5
### Added
- Quickfix avslutas om ett felaktigt kommando påträffas
- Applicerar protocol NO-OP på alla SSH-sessioner
- Möjlighet till loggning av alla ssh-sessioner
- Skrivit om hur SSH-sessioner hanteras för att göra rapporter snabbare genom att återanvända sessioner
- Stöd för SecureCRT 9.4 (Intern pre beta utvärdering)
### Changed
- Ställer in högsta möjliga STP prioritet som standard
- Vid konfiguration av KBN trunkport tas den höga STP prioriteten bort så att switch blir root
### Fixed
- Missförstånd med en funktion i API gjorde att en flik där script körs, fortfarande försökte stängas (från 2022.9.2)
- Inkonsekvent syftning i text och kommentarer

## 2.9.4
### Fixed
- Städat bort ett par bortglömda rader för tester
- Funktionen crt_connect_ssh städar nu inmatade värden från skräptecken
- I crt_connect_ssh kunde vissa kommandon detekteras felaktigt så att scriptet pausade
### Added
- Strukturerat om models.json med en ny hierarkisk struktur för samtliga interface
- Ny funktion för att skicka kommandon till flera enheter baserat på externa listor (quickfix)
### Changed
- Smart license har ändrats, ny konfiguration avspeglar detta

## 2.9.3
### Added
- När en trunk- eller access-port skapas sätts samtidigt unpluggable i Solarwinds

## 2.9.2
### Fixed
- Funktionen ping validerades felaktigt på ett par ställen
- Ändrat inkonsekventa svar från vissa funktioner
- Flik där script körs kan inte stängas

## 2.9.1
### Fixed
- Profilnamnet för Config Manager blev fel om uppgradering av moduler skedde samtidigt som Config Manager inte aktivt användes
- Förtydligat vilket konto som skall användas för DNS
- Saknade verifiering av DNS master innan provisionering och borttagning av enhet

## 2.7.1
### Added
- Ny versionsnumrering som bygger på datum och ett löpande versionsnummer
- Verifierar lokal sync av delade filer från Infras teams-kanal
- Optimerat hanteringen av installerade moduler
- Aktiverar automatisk uppdatering (Nyhet i SecureCRT 9.3)
- Stöd för switchen C9200L-24PXG-4X
- Funktion för att förhindra timeout på både serie- som ssh-sessioner när dialoger lämnas en längre tid
- Stöd för Python 3.10
- Koden verifieras nu även med Mypy
- Stöd för multigig i kombination med StackWise
- Sessionernas flik får ett namn efter vad de används till för tillfället
- Stöd för alla kända Prolific och FTDI chipsets
- Uppdatering av installerad Python
- Optimerat överföringen av uppgifter mellan moduler för SSH
- Hantering av idle-timeout i alla sessioner
### Fixed
- Logfil vid provisionering skapas inte korrekt
- Kontroll av kluster kan returnera olika stavning
- Fel encoding vid läsning av groups.json
- Rättat koden efter verifiering med Mypy
- "Auto qos global compact" stöds från 15.2.7
- SNMP location tillåter nu mer kombinationer
- Sätter inställning för delay i sessioner så att förutsättningar i scriptet stämmer när det körs
### Removed
- Tar bort stödet för SecureCRT 9.0 och 9.1
- Tar bort stöd för Python 3.8
- Tar bort stöd för MacOS, men bibehåller möjlighet att skala till andra os i framtiden

## 2.6.8
### Added
- Alla underfiler till scriptet ligger nu samlade i ett bibliotek
- Stöd för SecureCRT 9.3
- Stöd för IE-3300
### Fixed
- Automatiskt inventarienummer felade när man angav ett eget, samt stöd för test

## 2.6.7
### Added
- Ny funktion för manuell uppgradering och verifiering av programvaran i en switch
- Verifiering av inventarienummer så att det inte återanvänds
- Nästa lediga inventarienummer föreslås i dialogen, samt verifieras innan den allokeras
### Fixed
- Vid borttagning av switch kan det fela om man anger ip
- ise_delete_device kunde krascha under speciella omständigheter

## 2.6.6
### Fixed
- Hanterar krasch när felaktigt användarnamn anges för DNS-server
- Fel uppstod när image redan finns på switch med install mode
- Screen.Synchronous = True tas bort, hjälpte inte…
- crt_sendline har nu alltid en 175ms fördröjning för varje rad. Den dynamiska varianten kan fela ibland troligen pga seriebuffertfel

## 2.6.5
### Added
- Kan startas som ett script med argument via SecureCRT Button Bar, och då direkt starta ett menyalternativ och avsluta scriptet efteråt
### Fixed
- Städat bort funktion som glömts bort

## 2.6.4
### Added
- Ersätta funktion som frågar sessionsdatabas från ISE med DNA-Center istället. Ger mer och tillförlitligare information

## 2.6.3
### Added
- Snabbat på svar i dialoger där man kan välja mellan hostnamn och ipadress genom att inte vänta på dnsuppslag för ip

## 2.6.2
### Added
- Menyalternativ 41 försvinner. Switch anges istället i första dialogen i menyn

## 2.6.1
### Added
- Bättre dokumentation i port_trunk
- Nytt menyalternativ som ansluter en switch med ssh
### Fixed
- Rättat stavfel i kommentarer
- Förtydligat variabelnamn i put_personal_settings
- Rate-limit för API-anrop till DNA-Center

## 2.6.0
### Added
- Snabbat på installation och uppdatering av moduler vilket minskar antalet omstarter av SecureCRT
- Lägger till switch i DNA-Center
- Tar bort switch i DNA-Center
- Förbättrad hantering av strukturfel i json-filer
- Förenklad hantering av ISE noder i settings.json
- Koden är verifierad och rättad med Pylint
- Strukturerat retur av värde och status från funktioner
- About i menyn som tar användaren till systemdokumentationen
- Verifiering sker av att lokal biblioteksstruktur finns
- De ställen som använder "sh ip int brie" har fått en bättre regex-matchning
- Verifiering av att ett certifikat är betrott sker numera genom en variabel i settings.json
- Screen.Synchronous = True, används för att förhindra buffertfel
### Fixed
- Fel variabel användes i DNS_query när man angav ipadress
- Dokumentationen för Screen.WaitForString i SecureCRT stämmer inte, returnerar en integer och inte ett booelskt värde som det borde
- Timeout på API-förfrågningar för att inte fastna i en oändlig loop
- Funktionen add_vlans får felaktig lista med vlan
- Meny 12 har en oändlig while-loop
- Funktionen get_cluster gav fel om den inte användes via ssh
### Changed
- "logging monitor debug"

## 2.5.5
### Added
- De alternativ som går, låser sessionen när scriptet körs för att undvika oavsiktlig input
- Efter introduktion av DNS kan man nu ange både hostname, fqdn och ipadress i dialogerna
	
## 2.5.4
### Added
- Adderar även PTR i DNS
- Städat utseendet på menyer med input
- Låser sessionen vid provisionering för att förhindra oavsiktlig input
### Fixed
- Vissa endpoints skickade inte med all info vilket kraschade scriptet

## 2.5.3
### Added
- Likriktat alla input-dialoger
- Tydligare informationsrutor
- Nya alternativ 30 ger möjlighet att se var en enhet är ansluten genom dess mac. Man ges även möjlighet att ansluta till switchen som enheten ansluter till om det sker trådat.
### Changed
- aaa accounting update newinfo periodic 15 (Ändrat från 2880 minuter)

## 2.5.2
### Added
- Lägga till och ta bort DNS RR för switchens inventarienummer via PowerShell
- ISEFindDeviceByIP returnerar nu även hostname om ip existerar
- Input av namn på site blir striktare för att hantera DNSnamn korrekt

## 2.5.1
### Fixed
- Om man lämnar switchen mer än 60 minuter med en dialog, kommer exec-timeout göra att scriptet fallerar med att komma vidare då prompten är ändrad
- Fel i detektering av tidigare provisionerad switch

## 2.5.0
### Fixed
- Förbättrat och likriktat verifiering av ansluten enhet i ConnectSSH
- Lyckats använda type hints på ett inkonsekvent sätt, städat detta
- Använt default-värden i funktioner i för stor utsträckning vilket ställer till det vid felsökning
- Felet i SerialConnect från 2.4.2 blev aldrig riktigt löst, blev fel under andra omständigheter istället. Detta är nu löst genom att skriva om i stort sett hela funktionen
- Städat hur sökvägar anges i settings.json vilket var inkonsekvent angivet
- CheckExecMode kunde ibland fallera på äldre switchar som tog tid på sig efter första dialogen
- Ny dialog i CLI hanterades inte av CheckExecMode
- Använder ping istället för verifyinternet (som tas bort) då detta skapade ett moment 22 med kravet på requests
- Ett fel inträffade vid uppgradering av C9300-24S
- Upptäckte att seriebuffert fortfarande kunde slänga tecken, dock ytterst sällan. Lade in 25ms fördröjning för varje rad i SendLine
- Ett fel kunde inträffa vid uppgradering där image redan finns på flashen
### Added
- Stöd för Credentials Manager när SecureCRT version 9.2 används
- Alternativ 13 lägger nu till vlanet och namnar det
- Förbättrad felhantering av SSH-sessioner
- Verifiering av modellnummer när factory default sker för att undvika att fel typ av enheter rensas
- Översyn av funktioner i koden genom enhetlig namning och konsolidering
- Stadsnät-trunk kan nu inte skapas om man anger vlan som inte finns via stadsnätet
- Sätter globala inställningen "Single Instance" och default session inställningen "Auth prompt in windows"
- Sökväg till lokalt bibliotek för SecureCRT sätts nu i settings.json
- Hashning av nycklar och lösenord innan de skriv till skärmen, för att öka säkerheten vid inmatning och loggning
- Interface som inte används anges nu i models.json
- Stöd för multigig-portar som kan ha en helt annorlunda namnstandard
- Stöd för ny modell WS-C3560CX-8XPD-S och C9200L-24PXG-4X med multigig-portar
- Log med timestamp skapas vid provisionering för att fånga upp eventuella fel
- Detektering av NM på C9300 återuppstår
- Snyggat till header i menyn samt strukturerat listan för bättre läsbarhet
- Tagit bort IBNS2, blir omöjligt att underhålla den koden då den inte används skarpt
- SOLFindIP hanterar error 500 från webserver
- Tydligare dialog vid uppgradering när kabel skall anslutas eller tas bort
- Förhindra provisionering av redan provisionerad switch
- När man gör en extern accessport anpassas vissa inställningar om det gäller Lanbit
### Changed
- Version  12.2.55 gillar inte pipe efter "dir flash", byter till "show flash" istället
- Lade till "auto qos global compact" på utvalda modeller
- Lade till "dot1x timeout tx-period 7" i PortAccess
- Flyttat ISE specifika rader innanför villkoren för detta
- ISE Syslog till MNT tas bort
- Lade till "transport output none" på alla line

## 2.4.5
### Fixed
- Problem att detektera serieportar på nyare datorer, tagit bort notis om osupporterade serieportar
- Två fel i tab-objektet vid uppgradering

## 2.4.4
### Fixed
- För vissa switchar kunde man inte skapa access eller trunk port om den normalt sett inte skulle ha en sådan port
### Added
- Kontroll av modul i C9300 tas bort, är nu standard

## 2.4.3
### Added
- Kan nu lägga till en bredbandsenhet i ISE

## 2.4.2
### Fixed
- Rättat fel i inmatning av vlan, vlan mellan 50 och 99 ansågs ogiltiga
- Fel i uppgraderingen gjorde att en reload aldrig utfördes då en retur saknades
- Fel i funktionen SerialConnect gjorde att fel tab valdes, vilket kunde vara förödande

## 2.4.1
### Added
- Stöd för SecureCRT 9.2
- Fix i alternativ 20 tas bort, felet avhjälps genom att göra en ny ISE-port istället
- Alternativ 11 och 14 stänger porten tillfälligt under konfigurationen

## 2.4.0
### Fixed
- När en tab återanvändes blev den inte aktiv
- Optimerat vilka kommandon som skrivs till switchen medans man fortfarande kan avbryta provisioneringen
- Saknade en timeout för versionsverifieringen
### Added
- Stöd för att hämta adress till SNMP location från byggnadsregister via Excel
- Ny modul som kan översätta svenska tecken
- Verifiering sker att just en switch är ansluten i aktiv session
- Detekterar om scriptet exekverats i en CMD eller WSL-session, kunde annars fastna i en loop
- Inbyggd managementport sätts nu från models.json
- När ISE inte används skapas accessportarna, men utan access-vlan
- När KBN-trunk skapas, skapas nu även alla vlan i databasen och namnas rätt
- Versionsinformation i JSON-filerna
- Portar för API ställs nu i settings.json
- Alternativet för undantag skriver nu om hela portens konfiguration
- Nytt menyalternativ som ansluter alla anslutna serieportar
- Helt omarbetar anslutning med ssh, använder nu SecureCRT istället för en modul. Mycket snabbare!
- Möjlighet att detektera StackWise
### Changed
- AccessPort:
  Port-security städades
  Authentication event städades

## 2.3.7
### Fixed
- En viss typ av switch använder ett anpassat/felaktigt modellnummer på vissa ställen, vilket resulterar i att aktiv programversion inte detekteras

## 2.3.6
### Fixed
- Bytt tab mot space enligt PEP-8. Skapade problem i olika editorer
- GetVersion felade ibland och kraschade scriptet, när texten inte fångades från cli
- Missat att ange domain name och VTP domain i settings.json, istället för hårt i koden
- Exceptions är nu specifika enligt PEP-8
### Added
- Bättre hantering och återanvändning av seriesessioner, som redan finns i en tab
- Konsoliderat os-specifika inställningar till preChecks
- Settings och secret laddas nu inte i varje modul
- Dialogen runt att ange interfacenamn är förbättrad. Exemplet är en korrekt port för den modellen och funktion
### Changed
- "ip domain-lookup" skall numera vara "ip domain lookup"
- Syntax för smart token är ändrat på C9K

## 2.3.5
### Added
- Stöd för install mode för utvalda switchar
- Städat bort funktionen CleanFlash som integreras i övrig kod istället
- Automatisk omstart av switch efter uppgradering
- Lägger in omstart av SecureCRT efter uppgradering av Pythonmoduler
- Vid uppdatering eller installation av moduler valideras internetåtkomst
- Jämför hash av den lokalt lagrade nyckelfilen för att avgöra om den är ändrad
### Fixed
- Hanteringen av seriesessioner felar fortfarande, trimmat vilket värde den använder för utvärdering av ScriptTab
- Tagit bort kontroll av returncode efter uppgradering via PIP, dessa kan variera trots att de lyckas
- Diverse stavfel i dialoger
### Changed
- autoinstall är nu disablat som standard
- "ip domain-name" är ändrat till "ip domain name"
	
## 2.3.4
### Fixed
- En del mindre anpassningar efter kontakt med supporten hos Vandyke, och dokumentation

## 2.3.3
### Fixed
- Förbättrad hantering av seriesessioner. Kan nu hantera att flera serieadaptrar är anslutna
- Ett fel uppstår när inga tabbar är öppna och scriptet körs med alternativ som kräver en seriesession, temporär lösning i väntan på ärende

## 2.3.2
### Fixed
- Felaktig hantering när usb-adaptern inte är supporterad/känd
- Felaktig hantering när ingen usb-adapter är ansluten
- Något har hänt i Windows vilket gör att vissa adaptrar inte identifierades rätt. Har ändrat hur en adapter identifieras

## 2.3.1
### Added
- Stänger numera inte aktuell tab när man startar en seriesession
- Stänger seriesessionen efter sig
- Konsoliderade allt rörande ISE i settingsfilen
- Meny 5 sätter nu även profile id på utvalda devices
### Fixed
- I meny 5 står numera nu macadressen i meddelandet när den lyckats och när den inte hittat enheten
- Funktionen validatemac var inkonsekvent med vilken datatyp den svarade med
- Tydligare felmeddelanden när json-fil inte kan läsas
- Förtydligat texten i meny 4
- Förbättrat verifiering av jsondata när detta läses in
- Förbättrad hantering av seriesessioner
- Felstavning i meny 4 rättad
- Meny 14 gjorde en default av porten innan, vilket är fel
- ConnectSerial returnerade med inkonsekvent datatyp
### Changed
- Förbättrad säkerhet i ssh

## 2.3.0
### Added
- Gör om hur versionen på os kontrolleras. Ständigt fel med denna på något sätt, särskilt med IOS-XE
- Med ny funktion som läser version, kan "old_code" tas bort i models-filen
- MAC-validering stödjer nu ett till format: utan avgränsare
- Städat bland funktioner så att returnerat värde har samma format i alla applicerbara funktioner
- Flyttat device-sensor och device-tracker så att de även kommer med om man inte vill ha ISE
- Stöd för SecureCRT version 9.1
- Automatisk installation och uppdatering av moduler
- Stöd för personliga inställningar som lagras lokalt på datorn
- Förenklat koden som bygger menyn, var en rest från ett försök att bygga menyn utifrån en JSON-fil
- Anpassat settings.json för nya menyalternativ sex
- Adderat menyalternativ 21 och 22, två olika show kommandon
- Omarbetat hela funktionen GetModel för att göra den mer robust
- Börjat använda type hints i koden för funktioner
### Fixed
- Missat stödet för MacOS på sistone, lagat detta i de delar som hanterar sökvägar och enheter
- Rättat fel i models.json
- Städat importerade moduler
- Verifiering av certifikat verifierade fel port i vissa fall
- Regex för location tillät inte gatunamn med mellanslag
- Fel versionsinformation för vissa switchar i models.json
- Stängt sessionen efter lyckad validering av certifikat i ValidateCert
- Hantering av undantag (exceptions) i funktioner som läser json-filer
	
## 2.2.2
### Fixed
- Fel vid uppgradering när flashen redan innehåller filen, men inte är den aktiva
- Fel i accessport gjorde att en rad inte provisionerades i normala fall
- URL för nedladdning av secrets-filen var felkonstruerad

## 2.2.1
### Added
- Nu snabbare att skriva kommandon i cli
- Detekterar tidigare provisionerad switch
- Validering av macadress i meny 5
- Smart license är nu skalbar för framtida modeller genom "smartlicense" i models.json
- Management över L3 bestäms genom "layer3" i models.json
- Valbart stöd för IBNS 2.0, genom "ibns2" i models.json och networks.json (beta)
- Terminalens bredd ändrad till 150 tecken
- Meny 5 kan nu ta en kommaseparerad lista av macadresser
- Förfinat hur access och trunkportar selekteras, tagit bort ett modellberoende i koden
- Smart license går nu mot egen intern server
### Fixed
- Fixat fel som uppstår när ledigt utrymme på C9X skall räknas ut
- Fixat fel i Ping
- C9300-24S har inga accessportar, men scriptet trodde det. Är nu fixat

## 2.2.0
### Added
- Jag har överarbetat hur menyn byggs, men nu mer programmatiskt korrekt
- Uppgraderingsport tas nu fram dynamiskt istället för statiskt från modelno.csv
- All inläsning av inställningar sker numera från JSON-filer
- Verifiering av certifikat sker nu som standard
- Exec-timeout ökas från fem minuter till 15
- Flyttat all modellspecifik information till JSON-fil
- Kontroll av förkrav flyttad till egen funktion, som dessutom enbart exekveras vid uppstart
- Selektivt styra per vlan om karantän, telefoni eller ISE skall användas i networks.json
- Prefix på interfacenamn tas numera från models.json
- Alternativ 5, ändra id grupp för endpoint (MAB)
- Vissa "lite"-switchar har en hårdvarulimitering för hur många portar som kan använda exempelvis auto qos. Tar nu hänsyn till detta med "restrictedqos" i models.json
### Fixed
- Funktionen för att rensa flash använde fel variabel och skrev ut skräptecken istället. Funnits sedan pre 2.0
- CheckExec kunde fela ibland, lade in en timeout för den dialogen och omstart inom loopen
- Alternativ 13, extern accessport, är något uppstädad för bredare användningsområde
- Solarwinds discovery anpassat för C9300

## 2.1.1
### Added 
- Förbättrad hantering av PSN-noder 
### Fixed
- Regex för verifiering av vlan felar på nummer som slutar med en nolla, exempelvis 40

## 2.1.0
### Added
- Menyalternativ fyra som tar bort en enhet från Solarwinds och ISE, med validering att enbart en ip för accessnäten väljs
- Verifiering av certifikat är nu modulär, minskar komplexitet vid nya integrationer
- Uppdaterat matchning av interfacenamn att klara av 100Gb och 200Gb interface, samt stöd för Nexus
### Fixed
- Call-home kan fela när den namnupplöser över ipv6 istället för ipv4

## 2.0.4
### Added
- Login block vid upprepade inloggningsförsök
- Kräver ny modul, python-certifi-win32, som läser lokala certifikat i Windows
- Validering av certifikat i integrationen med ISE och Solarwinds
- Verifiering att API svarar korrekt innan menyalternativ exekveras
- Verifiering av installerade moduler
- Validering av vlan, interface och ipadress sker i separat funktion för lättare underhåll
### Fixed
- Integrationen mot ISE och Solarwinds använder inte global variabel för servernamn längre, något som glömdes kvar från pre 2.0
- Fel variabel i del av if-sats på ett par ställen, gjorde att dialogen inte kunde avslutas med cancel eller X
- Felstavning som påverkade portskapande för 3560CG, felaktig sträng
- Fel som kraschade scriptet i menyalternativ 10, använde fel variabel
	
## 2.0.3
### Added
- Trunkar blir inte längre unplugged i menyalternativ 3
### Fixed
- Använda Orion SDK för IPAM integrationen precis som andra delar som talar med Solarwinds API

## 2.0.2
### Fixed
- Cisco USB-adapter svarar med pid och vid som NoneType, vilket kraschar scriptet
	
## 2.0.1
### Added
- Randomisera ordningen för ip till dns, mnt-nod, ntp och psn-nod för att "lastbalansera"
- Tagit bort ett par rutor med positiv status som krävde interaktivitet i onödan
- Tagit bort Energywise

## 2.0.0
### Added
- Översatt till Python 3.8
- Menysystem ersätter de separata scripten
- Factory default och T2KBN är flyttade till nya menyn
- Bättre formatering, läsbarhet och hantering av json-kod i dialogen med REST API
- Kryptering av innehållet i lösenordsfilen som nu heter secret.enc. Versionsberoendet kan därmed tas bort, och ersätts med en nyckel som sparas i varje användares dator genom en dialog om filen saknas
- Stöd för Catalyst 1000-serien
- Härdat konfigurationen av IOS baserat på råd av Cisco. Bland annat inloggning enbart med SSHv2
- Städat boolesk hantering
- Städat hantering av modellspecifik konfiguration
- Möjlighet att addera nya enheter till Solarwinds och sätta rätt polling och egenskaper med RESP API
- Tagit bort stöd för cisco-phone på accessport
- Stöd för KBN3 tas bort
- Ping av enhet för verifiering att den är korrekt ansluten innan provisionering fortsätter
- Skapar automatiskt en session med ansluten serieport när det behövs. USB adapterns pid och vid måste finnas med i tuple tplPID och tplVID. Detta så att inte fel adapter väljs.
- Detekterar nystartad switch och hanterar den dialogen om auto install till priv exec
- Samtlig input har regex verifiering för att undvika krasch eller loopar
- Möjlighet att avsluta vid en dialog, var inte implementerat innan
- Menyalternativ för fix för autentiseringsbug av MAB
### Caveat
- Menyalternativ tre ger ingen feedback när det fungerar, och det tar en stund

## 1.9.2
### Changed
- Optimerat kod
- C9k saknade en trap för smart-license
- Funktion för paus efter ett range-kommando
- Optimerat CleanFlash för att använda funktionen FindImage
### Caveat
- Sista versionen med stöd för VBScript

## 1.9.1
### Fixed
- Rättat ordning när externa kodblock laddas
- Verifiering att det är en seriell session och inte ssh
- Problem med C9k som numera använder ny metod för uppgradering. Gjort om hela funktionen UpgradeCheck
	
## 1.9.0
### Added
- Flyttar ut kodblock gemensamma i externa filer som laddas efter behov. Förenklar uppdateringen av kod mellan scripten
- Verifierar all inmatning så att det är rätt formaterat. Skall hindra krasch när felaktigt värde matas in

## 1.8.2
### Fixed
- Optimerat Do…Loop
- Fixat fel i mode detektering som ibland inte fungerade om text skrevs till console av switchen
- Konsekvent användande av network(0)

## 1.8.1
### Fixed
- Rättat ett fel rörande med C9300-NM-8X
- Automatiserat dialogen runt C9300-NM-8X
 
## 1.8.0
### Added
- Ny models-fil med ny image för C9K
- Ny switch C9300-24S som enbart innehåller trunkportar
- Automatiserat upptäckt av befintliga vlan och management vlan i script för enstaka portar
- Detektering av 8x10Gb modul i C9300
- Om secretfile är inaktuell, öppnas ett nytt fönster där du kan ladda ned ny
- Detektering av exec, priv exec och config mode
### Changed
- Ändrat hantering av skapandet av trunkportar. Bytt från subrutin till funktion
- Ändrat skapandet av ise-portar. Bytt från subrutin till funktion
- Via ISE Accessport kan nu även klassiska trunkportar bli accessport med ISE
### Fixed
- Rättat dialogtext
- Rensat rester av uppdatering av C9K-modeller
- Fix för kvarlämnad konf för default-gateway eller route efter uppgradering har utförts
 
## 1.7.3
### Added
- Nätverks variablerna lagras nu i en separat fil så att man slipper editera koden inuti scriptet om detta skulle ändras. Introducerar därmed filen networks.csv på gemensam filyta.
- Scripten för enstaka portar har nu fått stöd för att köras på vilken port som helst i switchen.
- Tagit bort sidbrytning som kom med C9k i vissa funktioner
### Changed
- Går tillbaka till klassisk uppgradering på C9K
- Ändrat FreeMem till en function
- Ändrat ordning för aes kryptering för typ 0 lösenord är på väg bort i c9k
 
## 1.7.2
### Added
- Lagt till stöd för L3-tjänsten i KBN
- Stöd för dhcp snooping
- Stöd för IBNS 2.0 som är valbart på utvalda switchmodeller
- Lagt in en ACL för VTY access, som är best-practise
### Changed
- Ändrat paus i SendLine till 175ms
### Fixed
- Rättat fel i CleanFlash-modulen för 2960X

 
## 1.7.1
### Added
- Lagt till funktion för flow-control som gör att man slipper specialinställningar i sessionen
### Changed
- Ytterligare städat dialoger
- Bättre felhantering
### Fixed
- Problem med uppgraderingsmodulen. Skrivit om mycket kod för att hantera en egenhet som gör att ftp ibland inte fungerar.
- Glömt aktivera CleanFlash i version ## 1.7.0
- Två fel i global för 2960 med 15.0
 
## 1.7.0
### Added
- Verifierat uppgradering av C9K
### Changed
- Städat koden som hade blivit svår att hålla uppdaterad
- Likriktat konfig runt popup rutor samt städat antal och standardval
- Städat variabler
### Fixed
- Fixat ett fel som reserverade ip vid uppgradering
- Fixat verifiering av korrekt vlan
- Uppgradering felar ibland. Lade in 15sek fördröjning innan ftp-överföring
 
## 1.6.3
### Added
- Integration av Solarwinds för att hitta nästa lediga ip och markera den Reserved
 
## 1.6.2
### Added
- Verifiering av switchnamn och ip mot ISE ifall de redan finns
 
## 1.6.1
### Added
- Lagt till modul för ISE REST API som lägger till switchen som en ny network device
- Kontroll av version på secrets.dat
### Changed
- Ändrat ordning för factory default. Fick alltid upp en fråga om att spara konfig

## 1.6.0
### Added
- Introducerar fil för switchmodeller och dess unika inställningar
- Introducerar fil för nycklar, token och lösenord
- Fixat fel i uppdateringsmodulen som gjorde att felaktig konfiguration sparades vid omstart
- Städat variabler som används
- Lagt till modul som kontrollerar ledigt utrymme på flash
- Lagt till modul som kan rensa gamla .bin-filer
- Mer och bättre dokumentation i koden
- Konsoliderat bitar av switchkonfiguration
