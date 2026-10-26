@echo off
rem Portable Security Audit - Windows launcher for the SOURCE edition (development
rem and testing). Field use on targets should use the standalone
rem PortableSecurityAudit.exe built in Phase 8, which needs no Python.
rem
rem Launch MANUALLY. Right-click > "Run as administrator" for privileged checks.
setlocal
set "DIR=%~dp0"

if exist "%DIR%app\psatoolkit\__init__.py" (
    set "APP=%DIR%app"
    set "PSA_HOME=%DIR%"
) else if exist "%DIR%..\src\psatoolkit\__init__.py" (
    set "APP=%DIR%..\src"
    set "PSA_HOME=%DIR%.."
) else (
    echo Cannot find the psatoolkit package next to this launcher.
    exit /b 1
)

where py >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo Python launcher 'py' not found. Use PortableSecurityAudit.exe instead.
    exit /b 1
)

rem -I isolated mode ignores PYTHON* variables and user site-packages on the target.
py -3 -I -B -c "import sys; sys.path.insert(0, sys.argv.pop(1)); from psatoolkit.cli import main; sys.exit(main())" "%APP%" %*
exit /b %ERRORLEVEL%
