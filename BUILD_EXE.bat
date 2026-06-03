@echo off
setlocal EnableDelayedExpansion

REM ============================================================
REM  BUILD_EXE.bat  -  Build Code-2-TXT.exe with PyInstaller
REM
REM  Strictly requires Python 3.13.12.
REM  - If 3.13.12 is not found, prints the download link and stops.
REM  - Installs pinned build deps from requirements.txt.
REM  - Generates a Windows version resource from version.txt so the
REM    .exe shows the version in its file Properties > Details.
REM  Every message / stop point uses PAUSE so the window stays open.
REM ============================================================

REM Work from the folder this script lives in.
cd /d "%~dp0"

set "REQUIRED_VERSION=3.13.12"
set "PY_DOWNLOAD_URL=https://www.python.org/downloads/release/python-31312/"
set "APP_NAME=Code-2-TXT"
set "ENTRY=Code-2-TXT.py"

echo ============================================================
echo  Building %APP_NAME%.exe
echo  Required Python: %REQUIRED_VERSION%
echo ============================================================
echo.

REM ------------------------------------------------------------
REM 1) Locate a Python 3.13.12 interpreter.
REM    Prefer the py launcher (py -3.13), then fall back to python.
REM    We verify the EXACT full version string, not just 3.13.
REM ------------------------------------------------------------
set "PYEXE="

REM Try the py launcher pinned to 3.13 first.
where py >nul 2>&1
if %ERRORLEVEL%==0 (
    for /f "delims=" %%V in ('py -3.13 -c "import platform;print(platform.python_version())" 2^>nul') do set "FOUND=%%V"
    if "!FOUND!"=="%REQUIRED_VERSION%" (
        REM Resolve the actual interpreter path the launcher selected.
        for /f "delims=" %%P in ('py -3.13 -c "import sys;print(sys.executable)" 2^>nul') do set "PYEXE=%%P"
    )
)

REM Fall back to a bare 'python' on PATH if the launcher didn't match.
if not defined PYEXE (
    where python >nul 2>&1
    if !ERRORLEVEL!==0 (
        for /f "delims=" %%V in ('python -c "import platform;print(platform.python_version())" 2^>nul') do set "FOUND=%%V"
        if "!FOUND!"=="%REQUIRED_VERSION%" (
            for /f "delims=" %%P in ('python -c "import sys;print(sys.executable)" 2^>nul') do set "PYEXE=%%P"
        )
    )
)

if not defined PYEXE (
    echo.
    echo [ERROR] Python %REQUIRED_VERSION% was not found on this system.
    echo.
    echo This build requires EXACTLY Python %REQUIRED_VERSION%.
    if defined FOUND (
        echo The closest version detected was: !FOUND!
    ) else (
        echo No suitable Python interpreter was detected.
    )
    echo.
    echo Download Python %REQUIRED_VERSION% here:
    echo     %PY_DOWNLOAD_URL%
    echo.
    echo During install, tick "Add python.exe to PATH".
    echo After installing, re-run this script.
    echo.
    pause
    exit /b 1
)

echo [OK] Using Python %REQUIRED_VERSION%
echo      Interpreter: "%PYEXE%"
echo.

REM ------------------------------------------------------------
REM 2) Read the version from version.txt (single source of truth).
REM ------------------------------------------------------------
if not exist "version.txt" (
    echo [ERROR] version.txt not found next to this script.
    echo Create a version.txt containing a version like: 1.0.0
    echo.
    pause
    exit /b 1
)

set "APP_VERSION="
for /f "usebackq tokens=* delims= " %%L in ("version.txt") do (
    if not defined APP_VERSION set "APP_VERSION=%%L"
)
REM Trim stray spaces.
set "APP_VERSION=%APP_VERSION: =%"

if not defined APP_VERSION (
    echo [ERROR] version.txt is empty. Put a version like 1.0.0 in it.
    echo.
    pause
    exit /b 1
)

echo [OK] App version from version.txt: %APP_VERSION%
echo.

REM ------------------------------------------------------------
REM 3) Create / use a local virtual environment for a clean build.
REM ------------------------------------------------------------
set "VENV_DIR=.build-venv"
if not exist "%VENV_DIR%\Scripts\python.exe" (
    echo Creating build virtual environment in "%VENV_DIR%" ...
    "%PYEXE%" -m venv "%VENV_DIR%"
    if !ERRORLEVEL! neq 0 (
        echo [ERROR] Failed to create the virtual environment.
        echo.
        pause
        exit /b 1
    )
)
set "VPY=%VENV_DIR%\Scripts\python.exe"

echo Upgrading pip ...
"%VPY%" -m pip install --upgrade pip
if !ERRORLEVEL! neq 0 (
    echo [ERROR] Failed to upgrade pip.
    echo.
    pause
    exit /b 1
)
echo.

REM ------------------------------------------------------------
REM 4) Install pinned build requirements.
REM ------------------------------------------------------------
if not exist "requirements.txt" (
    echo [ERROR] requirements.txt not found next to this script.
    echo.
    pause
    exit /b 1
)

echo Installing build requirements from requirements.txt ...
"%VPY%" -m pip install -r requirements.txt
if !ERRORLEVEL! neq 0 (
    echo [ERROR] Failed to install build requirements.
    echo.
    pause
    exit /b 1
)
echo.

REM ------------------------------------------------------------
REM 5) Generate the Windows version resource from %APP_VERSION%.
REM    PyInstaller wants a 4-part numeric version (a,b,c,d).
REM ------------------------------------------------------------
echo Generating Windows version resource ...
"%VPY%" make_version_file.py "%APP_VERSION%" "%APP_NAME%" "file_version_info.txt"
if !ERRORLEVEL! neq 0 (
    echo [ERROR] Failed to generate the version resource file.
    echo.
    pause
    exit /b 1
)
echo.

REM ------------------------------------------------------------
REM 6) Build the one-file, windowed executable.
REM ------------------------------------------------------------
echo Building %APP_NAME%.exe with PyInstaller ...
"%VPY%" -m PyInstaller ^
    --noconfirm ^
    --clean ^
    --onefile ^
    --windowed ^
    --name "%APP_NAME%" ^
    --version-file "file_version_info.txt" ^
    "%ENTRY%"
if !ERRORLEVEL! neq 0 (
    echo.
    echo [ERROR] PyInstaller build failed. See the output above.
    echo.
    pause
    exit /b 1
)

echo.
echo ============================================================
echo  BUILD COMPLETE
echo  Output: "%CD%\dist\%APP_NAME%.exe"
echo  Version: %APP_VERSION%
echo ============================================================
echo.
echo Right-click the .exe ^> Properties ^> Details to see the version.
echo.
pause
exit /b 0
