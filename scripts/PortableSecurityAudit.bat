@echo off
rem Portable Security Audit - Windows launcher for the SOURCE edition (development
rem and testing). Field use on targets should use the standalone
rem PortableSecurityAudit.exe (docs/BUILD.md), which needs no Python.
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

rem Use the installed py launcher by absolute path: cmd.exe would otherwise search the
rem current directory and the host's PATH for "py" first.
set "PY="
if exist "%SystemRoot%\py.exe" set "PY=%SystemRoot%\py.exe"
if not defined PY if exist "%LOCALAPPDATA%\Programs\Python\Launcher\py.exe" set "PY=%LOCALAPPDATA%\Programs\Python\Launcher\py.exe"
if not defined PY (
    echo Python launcher py.exe not found. Use PortableSecurityAudit.exe instead.
    exit /b 1
)

rem -I isolated mode ignores PYTHON* variables and user site-packages on the target.
"%PY%" -3 -I -B -c "import sys; sys.path.insert(0, sys.argv.pop(1)); from psatoolkit.cli import main; sys.exit(main())" "%APP%" %*
exit /b %ERRORLEVEL%
