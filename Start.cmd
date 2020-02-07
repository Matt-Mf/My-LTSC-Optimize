@ECHO OFF
CD /D "%~dp0"

REM After setting the appropriate variables and switches, run this script as an administrator to quickly call Optimize-LTSC.
REM A list of all available variables and switches can be found inside Optimize-LTSC's .ps1 file.

REM Set the Optimize-LTSC Source Path variable.
SET "SourcePath=D:\ltsc\W10UI\Win10_17763.914_x64_2020-01-04.iso"

NET SESSION >NUL 2>&1
IF %ERRORLEVEL% NEQ 0 (
    ECHO Permission denied. This script must be run as an Administrator.
    ECHO:
    PAUSE
    EXIT
) ELSE (
    ECHO Running as Administrator.
    TIMEOUT /T 2 >NUL
    PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File .\Optimize-LTSC.ps1 -SourcePath "%SourcePath%" -WindowsApps "Select" -SystemApps -Packages -Features -Win7GUI -Registry -Additional -ISO
)
PAUSE
EXIT