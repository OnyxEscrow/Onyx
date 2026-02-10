@echo off
REM =============================================================================
REM NEXUS Security Assistant - Windows Setup Script
REM =============================================================================
title NEXUS Security Assistant - Wallet Setup

echo.
echo ========================================
echo    NEXUS Security Assistant v0.4.0
echo ========================================
echo.
echo Starting your LOCAL wallet service...
echo This keeps your keys PRIVATE and SECURE
echo.

REM Generate unique access code
set ACCESS_CODE=nexus_%RANDOM%_%TIME:~-2%
echo Your Access Code: %ACCESS_CODE%
echo.
echo COPY THIS CODE - You'll need it on the NEXUS website
echo.
pause

REM Check if monero-wallet-rpc exists
where monero-wallet-rpc.exe >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: monero-wallet-rpc.exe not found!
    echo Please install Monero from https://getmonero.org
    pause
    exit /b 1
)

REM Create wallet directory
if not exist "%USERPROFILE%\.nexus\wallets" (
    mkdir "%USERPROFILE%\.nexus\wallets"
)

echo.
echo Starting Monero Wallet RPC...
echo Port: 18083 (localhost only)
echo.
echo KEEP THIS WINDOW OPEN while using NEXUS!
echo.

monero-wallet-rpc.exe ^
    --testnet ^
    --rpc-bind-port 18083 ^
    --rpc-bind-ip 127.0.0.1 ^
    --disable-rpc-login ^
    --wallet-dir "%USERPROFILE%\.nexus\wallets" ^
    --log-level 1 ^
    --daemon-address http://stagenet.community.rino.io:38081

if %errorlevel% neq 0 (
    echo ERROR: Failed to start wallet RPC!
    pause
    exit /b 1
)

echo Wallet RPC stopped.
pause
