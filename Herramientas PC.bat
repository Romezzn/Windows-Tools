@echo off
chcp 65001
::==========================================
:: Administrador si o si
set _Args=%*
if "%~1" NEQ "" (
  set _Args=%_Args:"=%
)
fltmc 1>nul 2>nul || (
  cd /d "%~dp0"
  cmd /u /c echo Set UAC = CreateObject^("Shell.Application"^) : UAC.ShellExecute "cmd.exe", "/k cd ""%~dp0"" && ""%~dpnx0"" ""%_Args%""", "", "runas", 1 > "%temp%\GetAdmin.vbs"
  "%temp%\GetAdmin.vbs"
  del /f /q "%temp%\GetAdmin.vbs" 1>nul 2>nul
  exit
)
::==========================================
:inicio
cls
cd %~dp0
echo ¿Que quieres hacer?:
echo #
echo #
echo #	1) Detectar y Reparar errores de Windows
echo #	2) Abrir AppData
echo #	3) Eliminal archivos temporales y abrir limpiador de Windows
echo #	4) Escaneo de carpetas con un tamaño superior a 5GiB
echo #	5) Eliminar: Telemetría, Cortana y OneDrive
echo #	6) Activar GodMode(Escritorio)
echo #	7) Salir
echo #
echo #
set /p op=Selecciona una opción y pulsa [ENTER]:
if "%op%"=="1" goto reparar
if "%op%"=="2" goto aad
if "%op%"=="3" goto temp
if "%op%"=="4" goto carpetas
if "%op%"=="5" goto hex
if "%op%"=="6" goto GM
if "%op%"=="7" goto exit
if "%op%"=="test" goto test





::REPARAR WINDOWS
:reparar
cls
echo ¿Que quieres hacer?:
echo #
echo #
echo #	1) Escanear PC en busca de errores y reparar si es posible
echo #	2) Verificar imagen de Windows
echo #	3) Escanear imagen de Windows en busca de fallos
echo #	4) Reparar imagen de Windows
echo #	5) Volver al Menú Inicio
echo #
echo #
set /p op=Selecciona una opción y pulta [ENTER]:
if "%op%"=="1" goto rop1
if "%op%"=="2" goto rop2
if "%op%"=="3" goto rop3
if "%op%"=="4" goto rop4
if "%op%"=="5" goto inicio

::ESCANEA E INTENTA REPARAR ARCHIVOS CORRUPTOS
:rop1
cls
sfc /scannow
echo Presiona [ENTER] para volver al menú de Diagnostico y Reparación
pause >null
goto reparar


::COMPRUEBA LA IMAGEN DE WINDOWS CON UNA IMAGEN EN LINEA PARA COMPROBAR ARCHIVOS CORRUPTOS, DELATA PROBLEMAS SUPERFICIALES
:rop2
cls
DISM /Online /Cleanup-Image /CheckHealth
echo Presiona [ENTER] para volver al menú de Diagnostico y Reparación
pause >null
goto reparar

::COMPRUEBA LA IMAGEN DE WINDOWS CON UNA IMAGEN EN LINEA PARA COMPROBAR ARCHIVOS CORRUPTOS, DELATA PROBLEMAS CRITICOS DEL SISTEMA
:rop3
cls
DISM /Online /Cleanup-Image /ScanHealth
echo Presiona [ENTER] para volver al menú de Diagnostico y Reparación
pause >null
goto reparar

::REPARA TODOS LOS ARCHIVOS CORRUPTOS, PUEDE SOLUCIONAR MUCHOS PROBLEMAS
:rop4
cls
DISM /Online /Cleanup-Image /RestoreHealth
echo Presiona [ENTER] para volver al menú de Diagnostico y Reparación
pause >null
goto reparar


::ABRIR CARPETA APPDATA
:aad
cls
explorer %appdata%
goto inicio

::ELIMINAR TEMP
:temp
cls
cd %appdata%
cd ..
cd local
DEL /F /S /Q Temp
mkdir Temp
cls
echo Iniciando Limpiador integrado del Sistema.
echo Al finalizar las acciones con el limpiador podras continuar
cleanmgr.exe
cls
echo Presiona [ENTER] para volver al menú de Inicio
pause >null
goto inicio


::VER CARPETAS CON TAMAÑOS SUPERIORES A 5GB
:carpetas
cls
diskusage /minFileSize=5073741824 /h c:\
echo Presiona [ENTER] para volver al menú de Inicio
pause >null
goto inicio



::BORRAR WINDOWS.OLD
:bwo
cd \
DEL /F /S /Q Windows.old
echo Presiona [ENTER] para volver al menú de Inicio
pause >null
goto inicio





::ELIMINAR TCO
:hex
cls
echo ADVERTENCIA! 
echo #
echo #
echo #	Esta acción va a realizar cambios permanentes e irreversibles
echo #	en algunas caracteristicas del sistema operativo
echo #	Las acciones a realizar son:
echo #
echo #	- Eliminar Cortana
echo #	- Eliminar OneDrive
echo #	- Eliminar Publicidad de Microsoft
echo #	- Eliminar Telemetría
echo #
echo #	Usalo en caso sólo bajo tu responsabilidad
echo #
echo #
set /p op=Escribe s(si) para realizar las acciones descritas o n(no) para volver al Inicio:
if "%op%"=="s" goto hexs
if "%op%"=="n" goto inicio
:hexs
::TELEMETRIA
FOR /F "tokens=2*" %%a IN ('reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" /v "LastLoggedOnUserSID" 2^>nul') do (SET UID=%%b)
reg add "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\features\%UID%" /v "FeatureStates" /t REG_SZ /d "828" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Suggested Sites" /v "Enabled" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer" /v "AllowServicePoweredQSA" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete" /v "AutoSuggest" /t REG_SZ /d "no" /f
reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Infodelivery\Restrictions" /v "NoUpdateCheck" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Geolocation" /v "PolicyDisableGeolocation" /t REG_DWORD /d "1" /f
rem reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\Main" /v "Use FormSuggest" /t REG_SZ /d "no" /f
reg add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\Main" /v "DoNotTrack" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\Main" /v "FormSuggest Passwords" /t REG_SZ /d "no" /f
reg add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\SearchScopes" /v "ShowSearchSuggestionsGlobal" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" /v "AutoConnectAllowedOEM" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSync" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSyncUserOverride" /t REG_DWORD /d "1" /f
set datetime=%date% %time:~0,8%
net stop DiagTrack 
net stop diagnosticshub.standardcollector.service 
net stop dmwappushservice 
net stop WMPNetworkSvc 
sc config DiagTrack start=disabled 
sc config diagnosticshub.standardcollector.service start=disabled 
sc config dmwappushservice start=disabled 
sc config WMPNetworkSvc start=disabled 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d 1 /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d 1 /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f 
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d 0 /f 
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v "Start" /t REG_DWORD /d 0 /f 
DEL /q C:\ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl 
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f 
reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /f 
schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /Disable 
schtasks /Change /TN "Microsoft\Windows\Application Experience\AitAgent" /Disable 
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable 
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable 
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable 
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable 
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable 
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable 
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable 
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /Disable 
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\HypervisorFlightingTask" /Disable 
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable 
schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /Disable 
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /Disable 
schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable 
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /Disable 
schtasks /Change /TN "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /Disable 
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyMonitor" /Disable 
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyRefresh" /Disable 
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable 
reg add "HKLM\Software\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d "2" /f
reg add "HKEY_CURRENT_USER\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f 
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d 0 /f 
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /f 
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E5323777-F976-4f5b-9B55-B94699C46E44}" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2EEF81BE-33FA-4800-9670-1CD474972C3F}" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t REG_DWORD /d "5" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\DesktopTheme" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\StartLayout" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableSensors" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" /v "Status" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredUI" /v "DisablePasswordReveal" /t REG_DWORD /d 1 /f  
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WMDRM" /v "DisableOnline" /t REG_DWORD /d 1 /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d 1 /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d 1 /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d 1 /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreenCamera" /t REG_DWORD /d 1 /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d 0 /f 
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d 0 /f 
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d 0 /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Biometrics" /v "Enabled" /t REG_DWORD /d 0 /f 
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d 0 /f 
reg add "HKEY_CURRENT_USER\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d 1 /f 
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d 0 /f 

::PUBLICIDAD MICROSOFT Y TELEMATICA HOST
takeown /f "%SystemRoot%\System32\drivers\etc\hosts" /a
icacls "%SystemRoot%\System32\drivers\etc\hosts" /grant administrators:F
attrib -h -r -s "%SystemRoot%\System32\drivers\etc\hosts"

SET NEWLINE=^& echo.

FIND /C /I "tracking.opencandy.com.s3.amazonaws.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 tracking.opencandy.com.s3.amazonaws.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "media.opencandy.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 media.opencandy.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "cdn.opencandy.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 cdn.opencandy.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "racking.opencandy.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 tracking.opencandy.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "api.opencandy.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 api.opencandy.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "api.recommendedsw.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 api.recommendedsw.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "installer.betterinstaller.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 installer.betterinstaller.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "installer.filebulldog.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 installer.filebulldog.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "d3oxtn1x3b8d7i.cloudfront.net" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 d3oxtn1x3b8d7i.cloudfront.net>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "inno.bisrv.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 inno.bisrv.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "nsis.bisrv.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 nsis.bisrv.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "cdn.file2desktop.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 cdn.file2desktop.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "cdn.goateastcach.us" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 cdn.goateastcach.us>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "cdn.guttastatdk.us" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 cdn.guttastatdk.us>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "cdn.inskinmedia.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 cdn.inskinmedia.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "cdn.insta.oibundles2.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 cdn.insta.oibundles2.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "cdn.insta.playbryte.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 cdn.insta.playbryte.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "cdn.llogetfastcach.us" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 cdn.llogetfastcach.us>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "cdn.montiera.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 cdn.montiera.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "cdn.visualbee.net" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 cdn.visualbee.net>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "cdn.msdwnld.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 cdn.msdwnld.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "cdn.mypcbackup.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 cdn.mypcbackup.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "cdn.ppdownload.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 cdn.ppdownload.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "cdn.ppdownload.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 cdn.ppdownload.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "cdn.riceateastcach.us" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 cdn.riceateastcach.us>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "cdn.shyapotato.us" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 cdn.shyapotato.us>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "cdn.solimba.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 cdn.solimba.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "cdn.tuto4pc.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 cdn.tuto4pc.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "cdn.appround.biz" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 cdn.appround.biz>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "cdn.bigspeedpro.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 cdn.bigspeedpro.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "cdn.bispd.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 cdn.bispd.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "cdn.bisrv.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 cdn.bisrv.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "cdn.bisrv.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 cdn.bisrv.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "cdn.cdndp.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 cdn.cdndp.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "cdn.download.sweetpacks.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 cdn.download.sweetpacks.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "cdn.dpdownload.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 cdn.dpdownload.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "vortex.data.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 vortex.data.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "vortex-win.data.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 vortex-win.data.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "telecommand.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 telecommand.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "telecommand.telemetry.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 telecommand.telemetry.microsoft.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "oca.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 oca.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "oca.telemetry.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 oca.telemetry.microsoft.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "sqm.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 sqm.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "sqm.telemetry.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 sqm.telemetry.microsoft.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "watson.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 watson.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "watson.telemetry.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 watson.telemetry.microsoft.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "redir.metaservices.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 redir.metaservices.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "choice.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 choice.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "choice.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 choice.microsoft.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "df.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 df.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "wes.df.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 wes.df.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "reports.wes.df.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 reports.wes.df.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "services.wes.df.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 services.wes.df.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "sqm.df.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 sqm.df.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "watson.ppe.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 watson.ppe.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "telemetry.appex.bing.net" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 telemetry.appex.bing.net>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "telemetry.urs.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 telemetry.urs.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "telemetry.appex.bing.net:443" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 telemetry.appex.bing.net:443>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "settings-sandbox.data.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 settings-sandbox.data.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "vortex-sandbox.data.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 vortex-sandbox.data.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "survey.watson.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 survey.watson.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "watson.live.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 watson.live.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "watson.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 watson.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "statsfe2.ws.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 statsfe2.ws.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "corpext.msitadfs.glbdns2.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 corpext.msitadfs.glbdns2.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "compatexchange.cloudapp.net" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 compatexchange.cloudapp.net>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "cs1.wpc.v0cdn.net" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 cs1.wpc.v0cdn.net>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "a-0001.a-msedge.net" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 a-0001.a-msedge.net>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "statsfe2.update.microsoft.com.akadns.net" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 statsfe2.update.microsoft.com.akadns.net>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "sls.update.microsoft.com.akadns.net" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 sls.update.microsoft.com.akadns.net>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "fe2.update.microsoft.com.akadns.net" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 fe2.update.microsoft.com.akadns.net>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "diagnostics.support.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 diagnostics.support.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "corp.sts.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 corp.sts.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "statsfe1.ws.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 statsfe1.ws.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "pre.footprintpredict.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 pre.footprintpredict.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "i1.services.social.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 i1.services.social.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "i1.services.social.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 i1.services.social.microsoft.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "feedback.windows.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 feedback.windows.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "feedback.microsoft-hohm.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 feedback.microsoft-hohm.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "feedback.search.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO %NEWLINE%^127.0.0.1 feedback.search.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts



::CORTANA
net stop WSearch
sc config WSearch start= disabled
taskkill.exe /F /IM SearchUI.exe
cmd.exe /c takeown /f "%windir%\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy" /r /d s && icacls "%windir%\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy" /grant Administradores:F /t
taskkill.exe /F /IM SearchUI.exe
ren "%windir%\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe" "SearchUIC.exe"
rd /s /q "%windir%\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy"
Reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d "0" /f
taskkill /IM explorer.exe /F
explorer.exe
cls
echo Telemetria, Publicidad, OneDrive y Cortana Eliminados
echo Presiona [ENTER] para volver al menú de Inicio
pause >null
goto inicio





::ONEDRIVE
set x86="%ProgramFiles(x86)%\Microsoft OneDrive\OneDriveSetup.exe"
set x64="%ProgramFiles%\Microsoft OneDrive\OneDriveSetup.exe"
taskkill.exe /f /im OneDrive.exe
if exist %x64% (
%x64% /uninstall
) else (
%x86% /uninstall
)
rd "%USERPROFILE%\OneDrive" /Q /S
rd "%systemroot%/Users/%username%/OneDrive" /Q /S
rd "C:\OneDriveTemp" /Q /S
rd "%LOCALAPPDATA%\Microsoft\OneDrive" /Q /S
rd "%PROGRAMDATA%\Microsoft OneDrive" /Q /S
TASKKILL.exe /F /IM OneDrive.exe /T 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d 1 /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableLibrariesDefaultSaveToOneDrive" /t REG_DWORD /d 1 /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableMeteredNetworkFileSync" /t REG_DWORD /d 1 /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\Onedrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d 1 /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\Onedrive" /v "DisableLibrariesDefaultSaveToOneDrive" /t REG_DWORD /d 1 /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\Onedrive" /v "DisableMeteredNetworkFileSync" /t REG_DWORD /d 1 /f 
reg add "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d 0 /f 
reg add "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d 0 /f 
reg add "HKEY_CURRENT_USER\Software\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d 0 /f 
reg add "HKEY_CURRENT_USER\Software\Classes\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d 0 /f 
reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDrive" /f
takeown /F %Windir%\SysWOW64\OneDriveSetup.exe
icacls %Windir%\SysWOW64\OneDriveSetup.exe /grant Administradores:F
del %Windir%\SysWOW64\OneDriveSetup.exe
takeown /F %Windir%\SysWOW64\OneDriveSettingSyncProvider.dll
icacls %Windir%\SysWOW64\OneDriveSettingSyncProvider.dll /grant Administradores:F
del %Windir%\SysWOW64\OneDriveSettingSyncProvider.dll
Del %AppData%\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk 
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
REG DELETE "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
cls
echo Telemetria, Publicidad, OneDrive y Cortana Eliminados
echo Presiona [ENTER] para volver al menú de Inicio
pause >null
goto inicio



::CREAR CARPETA GODMODE EN ESCRITORIO
:GM


echo Set oWSH = CreateObject("WScript.Shell") >> "%temp%\GM.vbs"
echo Set oFSO = CreateObject("Scripting.FileSystemObject") >> "%temp%\GM.vbs"
echo godFolder = oWSH.SpecialFolders("Desktop") ^& "\GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}" >> "%temp%\GM.vbs"
echo If oFSO.FolderExists(godFolder) = False Then oFSO.CreateFolder(godFolder) >> "%temp%\GM.vbs"
cls
 "%temp%\GM.vbs"
 

cls
echo GodMode concedido
echo Presiona [ENTER] para volver al menú de Inicio
pause >null
goto inicio

:test
echo Descargando Unpark CPU
bitsadmin /transfer Unpark-CPU /download /priority normal ^
  "https://github.com/Romezzn/Windows-Tools/raw/e57947edf712b5b34c628eb53c0313180c643c9e/UCpu.exe" "%temp%\UCpu.exe"

echo Se ha finalizado la descarga del programa - Unpark CPU
pause
cls
Start %temp%\UCpu.exe
echo Presiona cualquier tecla para eliminar los archivos y continuar
pause
del /f /q "%temp%\UCpu.exe" 1>nul 2>nul
cls
echo Se han eliminado los archivos descargados
pause
goto inicio
:exit
::DEL /F /A *.bat
@exit