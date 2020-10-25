ECHO OFF

color 0a

TITLE GODSCRIPT

CD C:\

ECHO Updates set to automatic
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD 
/d 4 /f

:: Port 21 ::
ECHO Attempting to block port 21 (TCP/UDP ; IN/OUT)...
netsh advfirewall firewall add rule name="Block 21 FTP TCP IN" protocol=TCP dir=IN localport=21 action=BLOCK
netsh advfirewall firewall add rule name="Block 21 FTP UDP IN" protocol=UDP dir=IN localport=21 action=BLOCK
netsh advfirewall firewall add rule name="Block 21 FTP TCP OUT" protocol=TCP dir=OUT localport=21 action=BLOCK
netsh advfirewall firewall add rule name="Block 21 FTP UDP OUT" protocol=UDP dir=OUT localport=21 action=BLOCK
:: Port 22 ::
netsh advfirewall firewall add rule name="Block 22 SSH TCP IN" protocol=UDP dir=IN localport=22 action=BLOCK
netsh advfirewall firewall add rule name="Block 22 SSH UDP IN" protocol=TCP dir=IN localport=22 action=BLOCK
netsh advfirewall firewall add rule name="Block 22 SSH UDP OUT" protocol=UDP dir=OUT localport=22 action=BLOCK
netsh advfirewall firewall add rule name="Block 22 SSH TCP OUT" protocol=TCP dir=OUT localport=22 action=BLOCK
:: Port 23 ::
netsh advfirewall firewall add rule name="Block 23 Telnet TCP IN" protocol=TCP dir=IN localport=23 action=BLOCK
netsh advfirewall firewall add rule name="Block 23 Telnet UDP IN" protocol=UDP dir=IN localport=23 action=BLOCK
netsh advfirewall firewall add rule name="Block 23 Telnet UDP OUT" protocol=UDP dir=OUT localport=23 action=BLOCK
netsh advfirewall firewall add rule name="Block 23 Telnet TCP OUT" protocol=TCP dir=OUT localport=23 action=BLOCK
ECHO Finished attempt at blocking 21 (TCP/UDP ; IN/OUT).
ECHO Finished attempt at blocking 22 (TCP/UDP ; IN/OUT).
ECHO Finished attempt at blocking 23 (TCP/UDP ; IN/OUT).

sc config AppIDSvc start= demand
net stop AppIDSvc


sc config Appinfo start= demand
net start Appinfo


sc config AppHostSvc start= demand
net start AppHostSvc


sc config ALG start= demand
net stop ALG


sc config AppMgmt start= demand
net stop AppMgmt


sc config BITS start= demand
net start BITS


sc config BFE start= auto
net start BFE


sc config BDESVC start= auto
net start BDESVC


sc config PeerDistSvc start= demand
net stop PeerDistSvc


sc config wbengine start= demand
net stop wbengine


sc config bthserv start= disabled
net stop bthserv


sc config CertPropSvc start= disabled
net stop CertPropSvc


sc config KeyIso start= demand
net stop KeyIso


sc config EventSystem start= auto
net start EventSystem


sc config COMSysApp start= demand
net start COMSysApp


sc config Browser start= demand
net stop Browser


sc config VaultSvc start= demand
net stop VaultSvc


sc config CryptSvc start= auto
net start CryptSvc


sc config DcomLaunch start= disabled
net start DcomLaunch


sc config DoSvc start= auto
net start DoSvc


sc config DsmSvc start= auto
net start DsmSvc


sc config Dhcp start= auto
net start Dhcp


sc config CscService start= disabled
net stop CscService


sc config DPS start= automatic
net start DPS


sc config WdiServiceHost start= demand
net start WdiServiceHost


sc config WdiSystemHost start= demand
net start WdiSystemHost


sc config TrkWks start= demand
net stop TrkWks


sc config MSDTC start= demand
net start MSDTC


sc config Dnscache start= demand
net start Dnscache


sc config EFS start= disabled
net stop EFS


sc config Eaphost start= demand
net stop Eaphost


sc config Fax start= disabled
net stop Fax


sc config fhsvc start= disabled
net stop fhsvc

sc config ftpsvc start= disabled
net stop ftpsvc

sc config fdPHost start= demand
net stop fdPHost


sc config FDResPub start= demand
net stop FDResPub


sc config gpsvc start= auto
net start gpsvc


sc config HomeGroupListener start= disabled
net stop HomeGroupListener


sc config HomeGroupProvider start= demand
net stop HomeGroupProvider


sc config hidserv start= demand
net stop hidserv


sc config IKEEXT start= demand
net stop IKEEXT


sc config UI0Detect start= demand
net stop UI0Detect


sc config SharedAccess start= disabled
net stop SharedAccess


sc config iphlpsvc start= auto
net start iphlpsvc


sc config PolicyAgent start= demand
net stop PolicyAgent


sc config KtmRm start= demand
net stop KtmRm


sc config lltdsvc start= demand
net stop lltdsvc


sc config MSiSCSI start= disabled
net stop MSiSCSI


sc config swprv start= demand
net stop swprv


sc config NetTcpPortSharing start= disabled
net stop NetTcpPortSharing

sc config Netlogon start= disabled
net stop Netlogon

sc config Netman start= demand
net start Netman


sc config netprofm start= demand
net start netprofm


sc config NlaSv start= auto
net start NlaSvc


sc config nsi start= auto
net start nsi


sc config PNRPsvc start= demand
net stop PNRPsvc

sc config p2psvc start= demand
net stop p2psvc


sc config p2pimsvc start= demand
net stop p2pimsvc


sc config pla start= demand
net stop pla


sc config PlugPlay start= disabled
net stop PlugPlay


sc config PNRPAutoReg start= demand
net stop PNRPAutoReg


sc config WPDBusEnum start= demand
net start WPDBusEnum


sc config Power start= auto
net start Power


sc config Spooler start= disabled
net stop Spooler


sc config wercplsupport start= demand
net stop wercplsupport


sc config PcaSvc start= demand
net stop PcaSvc


sc config QWAVE start= disabled
net stop QWAVE


sc config RasAuto start= demand
net stop RasAuto


sc config RasMan start= demand
net stop RasMan


sc config SessionEnv start= disabled
net stop SessionEnv


sc config TermService start= disabled
net stop TermService

sc config UmRdpService start= disabled
net stop UmRdpService


sc config RpcSs start= disabled
net stop RpcSs


sc config RpcLocator start= disabled
net stop RpcLocator


sc config RemoteRegistry start= disabled
net stop RemoteRegistry


sc config RemoteAccess start= disabled
net stop RemoteAccess


sc config RpcEptMapper start= disabled
net stop RpcEptMapper


sc config seclogon start= disabled
net stop seclogon


sc config seclogon start= auto
net start LanmanServer


sc config SstpSvc start= demand
net stop SstpSvc


sc config SamSs start= auto
net start SamSs


sc config wscsvc start= auto
net start wscsvc


sc config ShellHWDetection start= auto
net start ShellHWDetection


sc config SCardSvr start= disabled
net stop SCardSvr


sc config SCPolicySvc start= disabled
net stop SCPolicySvc


sc config SNMPTRAP start= disabled
net stop SNMPTRAP


sc config sppsvc start= auto
net start sppsvc


sc config SSDPSRV start= demand
net start SSDPSRV


sc config StorSvc start= demand
net stop StorSvc


sc config SysMain start= auto
net start SysMain


sc config SENS start= auto
net start SENS


sc config Schedule start= auto
net start Schedule


sc config lmhosts start= auto
net start lmhosts


sc config TapiSrv start= disabled
net stop TapiSrv


sc config Themes start= auto
net start Themes


sc config upnphost start= demand
net stop upnphost


sc config ProfSvc start= auto
net start ProfSvc


sc config vds start= demand
net stop vds


sc config VSS start= demand
net stop VSS


sc config WebClient start= disabled
net stop WebClient


sc config Audiosrv start= auto
net start Audiosrv


sc config AudioEndpointBuilder start= auto
net start AudioEndpointBuilder


sc config SDRSVC start= demand
net stop SDRSVC


sc config WbioSrvc start= disabled
net stop WbioSrvc


sc config WcsPlugInService start= demand
net stop WcsPlugInService


sc config wcncsvc start= disabled
net stop wcncsvc


sc config WinDefend start= auto
net start WinDefend


sc config wudfsvc start= auto
net start wudfsvc


sc config WerSvc start= auto
net start WerSvc


sc config Wecsvc start= demand
net stop Wecsvc


sc config EventLog start= auto
net start EventLog

sc config MpsSvc start= auto
net start MpsSvc


sc config FontCache start= auto
net start FontCache


sc config stisvc start= demand
net stop stisvc


sc config msiserver start= demand
net stop msiserver


sc config Winmgmt start= auto
net start Winmgmt


sc config WMPNetworkSvc start= disabled
net stop WMPNetworkSvc


sc config TrustedInstaller start= demand
net stop TrustedInstaller


sc config FontCache3.0.0.0 start= demand
net stop FontCache3.0.0.0


sc config WinRM start= disabled
net stop WinRM


sc config WSearch start= auto
net start WSearch


sc config W32Time start= demand
net start W32Time


sc config wuauserv start= auto
net start wuauserv


sc config WinHttpAutoProxySvc start= demand
net stop WinHttpAutoProxySvc


sc config dot3svc start= demand
net stop dot3svc


sc config wmiApSrv start= demand
net stop wmiApSrv


sc config LanmanWorkstation start= auto
net start LanmanWorkstation


sc config WwanSvc start= demand
net stop WwanSvc

cd C:\

echo Creating hidden .txt file
dir /s/b/A:H *.txt > "C:\TXT_FILES_HIDDEN.txt"
echo Creating .txt file
dir /s/b *.txt > "C:\TXT_FILES.txt"

echo Creating hidden .exe file
dir /s/b/A:H *.exe > "C:\EXE_FILES_HIDDEN.txt"
echo Creating .exe file
dir /s/b *.exe > "C:\EXE_FILES.txt"

echo Creating hidden .bat file
dir /s/b/A:H *.bat > "C:\BAT_FILES_HIDDEN.txt"
echo Creating .bat file
dir /s/b *.bat > "C:\BAT_FILES.txt"

echo Creating hidden .mp3 file
dir /s/b/A:H *.mp3 > "C:\MP3_FILES_HIDDEN.txt"
echo Creating .mp3 file
dir /s/b *.mp3 > "C:\MP3_FILES.txt"

echo Creating hidden .jpg file
dir /s/b/A:H *.jpg > "C:\JPG_FILES_HIDDEN.txt"
echo Creating .jpg file
dir /s/b *.jpg > "C:\JPG_FILES.txt"

echo Creating hidden .html file
dir /s/b/A:H *.html > "C:\HTML_FILES_HIDDEN.txt"
echo Creating .html file
dir /s/b *.html > "C:\HTML_FILES.txt"

echo Creating hidden .mov file 
dir /s/b/A:H *.mov > "C:\MOV_FILES_HIDDEN.txt"
echo Creating .mov file
dir /s/b *.mov > "C:\MOV_FILES.txt"

echo Creating hidden .png file
dir /s/b/A:H *.png > "C:\PNG_FILES_HIDDEN.txt"
echo Creating .png file
dir /s/b *.png > "C:\PNG_FILES.txt"

echo Creating hidden .mp4 file
dir /s/b/A:H *.mp4 > "C:\MP4_FILES_HIDDEN.txt"
echo Creating .mp4 file
dir /s/b *.mp4 > "C:\MP4_FILES.txt"


echo Opening Host file
notepad C:\Windows\System32\drivers\etc\hosts

echo Opening mmc.exe to run .inf file
mmc.exe

echo.
echo ----- READ THIS IMPORTANT -----
echo ----- READ THIS IMPORTANT -----
echo ----- READ THIS IMPORTANT -----
echo.
echo The script is unable to: Start BitLocker Drive Encryption Service, Disabling Secondary Logon, 
echo Start Software Protection
echo.
echo GO INTO SERVICES: MANUALLY START Bitlocker Drive Encryption Service, set Seconday Logon's 
echo start-up to DISABLED, START Software Protection
echo.
echo ----- END OF MESSAGE -----
echo ----- END OF MESSAGE -----
echo ----- END OF MESSAGE -----
echo.
pause