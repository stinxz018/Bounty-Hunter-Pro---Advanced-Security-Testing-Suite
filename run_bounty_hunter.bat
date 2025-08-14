@echo off
title Bounty Hunter Pro - Advanced Security Testing Suite
echo.
echo 🎯 BOUNTY HUNTER PRO
echo =====================
echo.
echo Starting application...
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python is not installed or not in PATH
    echo Please install Python 3.7+ from https://python.org
    pause
    exit /b 1
)

REM Run the application
python bounty_hunter_gui.py

REM Keep window open if there's an error
if errorlevel 1 (
    echo.
    echo ❌ Application encountered an error
    pause
)

