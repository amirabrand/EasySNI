@echo off
REM ============================================================
REM  V2RayEz - interactive build for all platforms (Windows)
REM  Output goes to .\dist\
REM  Lets you choose extra build tags (Psiphon / LiveKit) and
REM  fetches their dependencies automatically.
REM ============================================================
setlocal enabledelayedexpansion
cd /d "%~dp0"

set APP=v2rayez
set OUT=dist
set GOTOOLCHAIN=local
set CGO_ENABLED=0

echo.
echo ===============================================
echo            V2RayEz  -  build-all
echo ===============================================
echo.
echo  Build profile (extra features via Go build tags):
echo.
echo    [1] Standard            (recommended, no extra deps)
echo    [2] With Psiphon        (fetches psiphon-tunnel-core)
echo    [3] With LiveKit        (fetches livekit server-sdk)
echo    [4] All tags            (Psiphon + LiveKit)
echo.
set "PROFILE="
set /p PROFILE=Enter choice [1-4] (default 1): 
if "%PROFILE%"=="" set PROFILE=1

set "TAGS="
if "%PROFILE%"=="2" set "TAGS=psiphon"
if "%PROFILE%"=="3" set "TAGS=livekit"
if "%PROFILE%"=="4" set "TAGS=psiphon livekit"

echo.
echo  Targets:
echo    [1] All platforms (Windows/macOS/Linux x amd64/arm64)
echo    [2] Windows only (this machine, fastest)
echo.
set "TARGETS="
set /p TARGETS=Enter choice [1-2] (default 1): 
if "%TARGETS%"=="" set TARGETS=1

echo.
if defined TAGS (
  echo [*] Build tags: %TAGS%
  echo [*] Fetching tag dependencies ^(needs internet^)...
  echo %TAGS% | findstr /C:"psiphon" >nul && (
    echo.
    echo     [!] Embedded Psiphon is NOT fetchable with 'go get'.
    echo         psiphon-tunnel-core uses a local-path replace and forked
    echo         quic-go/utls, and needs Go 1.26+. See PSIPHON.md.
    echo         Recommended instead: use the "Start Psiphon over MITM" button
    echo         in the app and point the Psiphon APP's upstream proxy at it.
    echo         Continuing without the psiphon tag...
    echo.
    set "TAGS=!TAGS:psiphon=!"
  )
  echo %TAGS% | findstr /C:"livekit" >nul && (
    echo     - go get livekit server-sdk
    go get github.com/livekit/server-sdk-go/v2@latest
  )
  echo     - go mod tidy
  go mod tidy
) else (
  echo [*] Build tags: ^(none - standard build^)
)

if not exist "%OUT%" mkdir "%OUT%"

REM build a -tags flag only when tags are set (avoids empty-quote issues)
set "TAGFLAG="
if defined TAGS set TAGFLAG=-tags "%TAGS%"

echo.
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
go build -trimpath %TAGFLAG% -ldflags "-s -w" -o "%OUT%\%APP%-windows-amd64.exe" .
if errorlevel 1 goto :builderr

set GOARCH=arm64
echo   - windows/arm64
go build -trimpath %TAGFLAG% -ldflags "-s -w" -o "%OUT%\%APP%-windows-arm64.exe" .

REM .syso only affects Windows builds; remove so other targets stay clean
del /q resource_windows_amd64.syso resource_windows_arm64.syso 2>nul

if "%TARGETS%"=="2" goto :done

set GOOS=darwin
set GOARCH=amd64
echo   - macos/amd64 (Intel)
go build -trimpath %TAGFLAG% -ldflags "-s -w" -o "%OUT%\%APP%-macos-amd64" .

set GOARCH=arm64
echo   - macos/arm64 (Apple Silicon)
go build -trimpath %TAGFLAG% -ldflags "-s -w" -o "%OUT%\%APP%-macos-arm64" .

set GOOS=linux
set GOARCH=amd64
echo   - linux/amd64
go build -trimpath %TAGFLAG% -ldflags "-s -w" -o "%OUT%\%APP%-linux-amd64" .

set GOARCH=arm64
echo   - linux/arm64
go build -trimpath %TAGFLAG% -ldflags "-s -w" -o "%OUT%\%APP%-linux-arm64" .

:done
set GOOS=
set GOARCH=
echo.
echo === Done. Binaries are in "%OUT%\" ===
dir /b "%OUT%"
echo.
echo Tip: to build manually, put -tags BEFORE the dot, e.g.:
echo     go build -tags psiphon .
echo.
pause
goto :eof

:builderr
del /q resource_windows_amd64.syso resource_windows_arm64.syso 2>nul
echo.
echo *** BUILD FAILED ***
if defined TAGS echo If a tagged build failed, make sure you have internet for 'go get' and try 'go mod tidy' again.
echo.
pause
