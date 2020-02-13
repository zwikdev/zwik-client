@echo off
:: This file demonstrates the "--single-package"
::  feature.
::
:: When called it will automatically start a Python shell
::  using the technology of the Zwik client
::
:: Do not change this file!
:: file integrity: 6e0fcb5d681f31940c9ddc873380a073

setlocal
set ZWIK_BOOT_VERSION=7
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
  set ZWIK_INSTALLER=%TEMP%\zwik-install.bat
  set URL=%ZWIK_URL%/zwik-install.bat
  :: Also try download using powershell to be compatible with older systems (like Windows 7)
  curl -f -# "%URL%" -o "%ZWIK_INSTALLER%" || powershell -Command "(New-Object Net.WebClient).DownloadFile('%URL%', '%ZWIK_INSTALLER%')" || exit /B 1

  :RUN_INSTALL_SCRIPT
  echo Running install script, this can take a while
  call %ZWIK_INSTALLER% || exit /B 1

:RUN_ZWIK_CLIENT_SCRIPT
call "%ZWIK_ROOT%\python.exe" "%ZWIK_CLIENT_SCRIPT%" --single-package python --update-all --update-interval 48 --no-wait --exec python.exe %*
