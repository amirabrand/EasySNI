@echo off
REM ============================================================
REM  V2RayEz - build for all platforms  (run on Windows)
REM  Output goes to .\dist\
REM  The Windows .exe gets the app icon embedded via goversioninfo.
REM ============================================================
setlocal enabledelayedexpansion
cd /d "%~dp0"

set APP=v2rayez
set OUT=dist
if not exist "%OUT%" mkdir "%OUT%"

REM keep builds reproducible / avoid toolchain downloads
set GOTOOLCHAIN=local
set CGO_ENABLED=0

echo.
echo === V2RayEz build-all ===
echo.

REM ---- embed the Windows icon (best effort) ----
echo [*] Preparing Windows icon resource...
where goversioninfo >nul 2>nul
if %errorlevel%==0 (
  goversioninfo -64 -icon=docs\logo.ico -o resource_windows_amd64.syso versioninfo.json
  goversioninfo -arm -64 -icon=docs\logo.ico -o resource_windows_arm64.syso versioninfo.json 2>nul
) else (
  echo     goversioninfo not found - fetching it once via 'go run' ...
  go run github.com/josephspurrier/goversioninfo/cmd/goversioninfo@latest -64 -icon=docs\logo.ico -o resource_windows_amd64.syso versioninfo.json
  go run github.com/josephspurrier/goversioninfo/cmd/goversioninfo@latest -arm -64 -icon=docs\logo.ico -o resource_windows_arm64.syso versioninfo.json 2>nul
)
if not exist resource_windows_amd64.syso echo     ^(icon embed skipped - building without a custom icon^)

echo.
echo [*] Building...

set GOOS=windows
set GOARCH=amd64
echo   - windows/amd64
go build -trimpath -ldflags "-s -w" -o "%OUT%\%APP%-windows-amd64.exe" .

set GOARCH=arm64
echo   - windows/arm64
go build -trimpath -ldflags "-s -w" -o "%OUT%\%APP%-windows-arm64.exe" .

REM .syso only affects Windows builds; remove so other targets stay clean
del /q resource_windows_amd64.syso resource_windows_arm64.syso 2>nul

set GOOS=darwin
set GOARCH=amd64
echo   - macos/amd64 (Intel)
go build -trimpath -ldflags "-s -w" -o "%OUT%\%APP%-macos-amd64" .

set GOARCH=arm64
echo   - macos/arm64 (Apple Silicon)
go build -trimpath -ldflags "-s -w" -o "%OUT%\%APP%-macos-arm64" .

set GOOS=linux
set GOARCH=amd64
echo   - linux/amd64
go build -trimpath -ldflags "-s -w" -o "%OUT%\%APP%-linux-amd64" .

set GOARCH=arm64
echo   - linux/arm64
go build -trimpath -ldflags "-s -w" -o "%OUT%\%APP%-linux-arm64" .

set GOOS=
set GOARCH=

echo.
echo === Done. Binaries are in "%OUT%\" ===
dir /b "%OUT%"
echo.
pause
