@echo off
echo ============================================================
echo   VulnShot POC - Quick Test
echo ============================================================
echo.

REM Install dependencies
echo Installing dependencies...
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo.
    echo ERROR: Failed to install dependencies
    pause
    exit /b 1
)

echo.
echo Installing Playwright browsers...
playwright install chromium
if %errorlevel% neq 0 (
    echo.
    echo ERROR: Failed to install Playwright
    pause
    exit /b 1
)

echo.
echo ============================================================
echo   Running Test
echo ============================================================
echo.

python test_vulnshot.py

if %errorlevel% equ 0 (
    echo.
    echo ============================================================
    echo   Opening report...
    echo ============================================================
    start test_output\vulnshot_report.html
)

pause

