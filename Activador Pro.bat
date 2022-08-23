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


:Pro
echo Instalando serial de tu elección

slmgr /ipk W269N-WFGWX-YVC9B-4J6C9-T83GX

pause
cls
goto fin


:fin
echo Instalando Servidor de KMS
slmgr /skms kms.digiboy.ir
pause
cls
echo Continue para terminar la activación
pause
cls
slmgr /ato
pause
goto Salir


:Salir
cls
echo Adios
pause