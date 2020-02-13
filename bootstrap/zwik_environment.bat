@echo off
:: This file belongs to the Zwik client
::  run it to activate the Zwik environment
::  please commit this file to your version control system
::
:: Do not change this file!
:: file integrity: c6bf1dd67ee4ba7bc6107fea8d3587a9

setlocal
set ZWIK_BOOT_VERSION=8
set ZWIK_BOOT_SCRIPT=%~f0
:: Set variable if not already defined
if "%ZWIK_ROOT%"=="" set ZWIK_ROOT=%LOCALAPPDATA%\zwik
if "%ZWIK_URL%"=="" set ZWIK_URL=https://zwikdev.github.io
if "%ZWIK_CLIENT_SCRIPT%"=="" set ZWIK_CLIENT_SCRIPT=%ZWIK_ROOT%\zwik_client.py
:: Check if installation is ok
call "%ZWIK_ROOT%\python.exe" "%ZWIK_CLIENT_SCRIPT%" --version >nul && goto RUN_ZWIK_CLIENT_SCRIPT

  echo Zwik is not installed, or not completely
  if not "%ZWIK_INSTALLER%"=="" (
    echo WARNING: Running custom installer script
    goto RUN_INSTALL_SCRIPT
  )
  set ZWIK_INSTALLER=%TEMP%\%RANDOM%-zwik-install.bat
  set URL=%ZWIK_URL%/zwik-install.bat
  :: Also try download using powershell to be compatible with older systems (like Windows 7)
  curl -f -# "%URL%" -o "%ZWIK_INSTALLER%" || powershell -Command "(New-Object Net.WebClient).DownloadFile('%URL%', '%ZWIK_INSTALLER%')" || exit /B 1

  :RUN_INSTALL_SCRIPT
  echo Running install script, this can take a while
  call %ZWIK_INSTALLER% || exit /B 1

:RUN_ZWIK_CLIENT_SCRIPT
call "%ZWIK_ROOT%\python.exe" "%ZWIK_CLIENT_SCRIPT%" %*
