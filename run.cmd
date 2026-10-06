@echo off
REM NVD Switch Lab launcher - Windows. Double-click, or: run.cmd query --cve CVE-2024-3400
setlocal
cd /d "%~dp0"

set ARGS=%*
if "%ARGS%"=="" set ARGS=doctor

REM The Windows Store stub "python" exits 9009 if Python is not really installed,
REM so check py.exe (the official launcher) first.
REM
REM This uses "if errorlevel N" with goto instead of "if %ERRORLEVEL%==0 ( ... )".
REM %ERRORLEVEL% inside a parenthesized block is substituted once, when the block
REM is parsed, before anything inside it runs - so a command run earlier in that
REM same block never updates it. goto-based branching has no such block to parse
REM ahead of time, so each check sees the real exit code of the command before it.
where py >nul 2>&1
if errorlevel 1 goto :trypython
py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3,8) else 1)" >nul 2>&1
if errorlevel 1 goto :trypython
py -3 lab.py %ARGS%
goto :done

:trypython
where python >nul 2>&1
if errorlevel 1 goto :nopython
python -c "import sys; sys.exit(0 if sys.version_info >= (3,8) else 1)" >nul 2>&1
if errorlevel 1 goto :nopython
python lab.py %ARGS%
goto :done

:nopython
echo.
echo Python 3.8 or newer was not found on this machine.
echo.
echo   Fastest fix: open the Microsoft Store, search "Python 3", install it,
echo   then close and reopen this window.
echo.
echo   Or download from https://python.org/downloads
echo   (tick "Add python.exe to PATH" in the installer).
echo.

:done
echo.
pause
endlocal
