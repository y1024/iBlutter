@echo off
:: iBlutter - Quick Launch Wrapper for Windows
:: Usage: iblutter.bat -i MyApp.ipa -o output\
echo.
echo   iBlutter - iOS Flutter Reverse Engineering Tool
echo   ─────────────────────────────────────────────
echo.
python "%~dp0iblutter.py" %*
