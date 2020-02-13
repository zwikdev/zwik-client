@echo off
set CONDA_INSTALLER_WIN=Miniforge3-24.3.0-0-Windows-x86_64.exe
set CONDA_NAME=Mambaforge

if "%ZWIK_URL%"=="" goto ENV_ERROR
if "%ZWIK_CLIENT_SCRIPT%"=="" goto ENV_ERROR
if "%ZWIK_ROOT%"=="" goto ENV_ERROR
goto ENV_OK

:ENV_ERROR
echo ERROR: not all necessary environment variables are set
exit /B 1

:ENV_OK

if "%ZWIK_ROOT:~0,10%"=="C:\Windows" (
  echo Environment variable ZWIK_ROOT is not specified or set to an invalid value
  exit /B 1
)

if exist "%ZWIK_ROOT%.uninstall" (
  rem For loop below is used to check if the Conda root folder is empty
  rem  An error is shown if not as this indicates an uninstall is in progress
  for %%A in (%ZWIK_ROOT%\*) do (
    echo Conda uninstall in progress, this can take some time
    echo If it takes too long, reboot and delete "%ZWIK_ROOT%"
    exit /B 1
  )
)
if exist "%ZWIK_ROOT%.uninstall" (
  echo Previous Conda version is successfully uninstalled, remove lock file
  del "%ZWIK_ROOT%.uninstall"
)

if exist "%ZWIK_ROOT%\python.exe" (
  echo %CONDA_NAME% already installed! (at %ZWIK_ROOT%^)
  goto INSTALL_SCRIPT
)

echo Install %CONDA_NAME% (at %ZWIK_ROOT%^)
if exist "%ZWIK_ROOT%" (
  echo Please remove the following directory manually: %ZWIK_ROOT%
  exit /B 1
)

echo Fetching installer
set /A retries=3

:FETCH_INSTALLER
curl -f -# "%ZWIK_URL%/install-data/%CONDA_INSTALLER_WIN%" -o "%TEMP%\conda-install.exe" || powershell -Command "$output='%TEMP%\conda-install.exe'; Invoke-WebRequest -Uri '%ZWIK_URL%/install-data/%CONDA_INSTALLER_WIN%' -OutFile $output" || exit /B 1

if %ERRORLEVEL% == 0 ( goto VERIFY_INSTALLER )

:HANDLE_RETRY
if %retries% gtr 0 (
  timeout 5 > nul
  echo Retrying...
  set /A retries-=1
  goto FETCH_INSTALLER
) else ( exit /B 1 )

:VERIFY_INSTALLER
if not exist "%TEMP%\conda-install.exe" (
  exit /B 1
)

echo Running installer
start /wait "" %TEMP%\conda-install.exe /S /RegisterPython=0 /AddToPath=0 /D=%ZWIK_ROOT%
del "%TEMP%\conda-install.exe"
rem workaround for SSL: https://github.com/conda/conda/issues/8273
xcopy /I /Q %ZWIK_ROOT%\Library\bin\libcrypto-1_1-x64.* %ZWIK_ROOT%\DLLs\
xcopy /I /Q %ZWIK_ROOT%\Library\bin\libssl-1_1-x64.* %ZWIK_ROOT%\DLLs\

:INSTALL_SCRIPT
if exist "%ZWIK_CLIENT_SCRIPT%" (
  echo Zwik client already installed!
  goto CHECK_INSTALLATION
)
echo Fetching Zwik client script (%ZWIK_CLIENT_SCRIPT%^)
SETLOCAL
set zwik_script_url=%ZWIK_URL%/install-data/zwik_client.py
set zwik_settings_url=%ZWIK_URL%/install-data/zwik_client_settings.py
if defined ZWIK_CLIENT_URL (
  set zwik_script_url=%ZWIK_CLIENT_URL%
  set zwik_settings_url=%ZWIK_CLIENT_URL:.py=_settings.py%
)

curl -f -# "%zwik_settings_url%" -o "%TEMP%\zwik-tmp-settings.py" || powershell -Command "$output='%TEMP%\zwik-tmp-settings.py'; Invoke-WebRequest -Uri '%zwik_settings_url%' -OutFile $output" || exit /B 1
curl -f -# "%zwik_script_url%" -o "%TEMP%\zwik-tmp.py" || powershell -Command "$output='%TEMP%\zwik-tmp.py'; Invoke-WebRequest -Uri '%zwik_script_url%' -OutFile $output" || exit /B 1

:MOVE_FILES
ENDLOCAL
for %%F in (%ZWIK_CLIENT_SCRIPT%) do set client_name=%%~nxF
move "%TEMP%\zwik-tmp-settings.py" "%ZWIK_ROOT%\%client_name:.py=_settings.py%"
move "%TEMP%\zwik-tmp.py" "%ZWIK_CLIENT_SCRIPT%"

:CHECK_INSTALLATION
rem Reset %ERRORLEVEL% to 0
ver > nul
if "%SKIP_INSTALLATION_CHECK%"=="" (
  call "%ZWIK_ROOT%\python.exe" "%ZWIK_CLIENT_SCRIPT%" --check-installation --fix
)
