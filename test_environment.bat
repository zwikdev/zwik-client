@echo off
if not "%WORKSPACE%" == "" (
    @set ZWIK_ROOT=%WORKSPACE%\conda_tmp_root
)

@set SCRIPT_DIR=%~dp0
@set ZWIK_CLIENT_SCRIPT=%SCRIPT_DIR%scripts\zwik_client.py
@set ZWIK_INSTALLER=%SCRIPT_DIR%scripts\zwik-install.bat
@set SKIP_INSTALLATION_CHECK=1
@call %SCRIPT_DIR%bootstrap\zwik_environment.bat --environment %SCRIPT_DIR%.zwik\zwik_environment.yml %*
