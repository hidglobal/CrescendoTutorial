@echo off
setlocal enabledelayedexpansion

REM Default values
set ARCH=x64
set CONFIG=Release

REM Parse command line arguments
:parse_args
if "%1"=="" goto end_parse_args
if /i "%1"=="x86" set ARCH=x86& goto next_arg
if /i "%1"=="x64" set ARCH=x64& goto next_arg
if /i "%1"=="arm64" set ARCH=arm64& goto next_arg
if /i "%1"=="debug" set CONFIG=Debug& goto next_arg
if /i "%1"=="release" set CONFIG=Release& goto next_arg
echo Unknown argument: %1
goto usage
:next_arg
shift
goto parse_args
:end_parse_args

echo Building CrescendoTutorial for %ARCH% in %CONFIG% mode...

REM Ensure output directories exist
if not exist build\%ARCH%\%CONFIG% mkdir build\%ARCH%\%CONFIG%

REM Set compiler flags based on configuration
set COMMON_FLAGS=/nologo /EHsc /W4 /wd4100 /std:c++14 /D_UNICODE /DUNICODE
if /i "%CONFIG%"=="Debug" (
    set CONFIG_FLAGS=/Od /Zi /MDd /D_DEBUG /Fd"build\%ARCH%\%CONFIG%\CrescendoTutorial.pdb"
    set LINK_FLAGS=/DEBUG
) else (
    set CONFIG_FLAGS=/O2 /GL /MD /DNDEBUG
    set LINK_FLAGS=/LTCG /OPT:REF /OPT:ICF
)

REM Set architecture-specific flags
if /i "%ARCH%"=="x86" (
    set ARCH_FLAGS=
) else if /i "%ARCH%"=="x64" (
    set ARCH_FLAGS=/D_WIN64
) else if /i "%ARCH%"=="arm64" (
    set ARCH_FLAGS=/D_WIN64 /D_ARM64
) else (
    echo Unsupported architecture: %ARCH%
    goto usage
)

REM Compile and link
cl %COMMON_FLAGS% %CONFIG_FLAGS% %ARCH_FLAGS% CrescendoTutorial.cpp /Fo"build\%ARCH%\%CONFIG%\CrescendoTutorial.obj" /Fe"build\%ARCH%\%CONFIG%\CrescendoTutorial.exe" /link %LINK_FLAGS% ncrypt.lib winscard.lib scarddlg.lib comctl32.lib advapi32.lib shell32.lib user32.lib ole32.lib /SUBSYSTEM:CONSOLE

REM Check if build succeeded
if %ERRORLEVEL% == 0 (
    echo Build successful.
    echo Executable is at: build\%ARCH%\%CONFIG%\CrescendoTutorial.exe
    
    REM Copy INI file to output directory if it exists
    if exist CrescendoTutorial.ini (
        copy /Y CrescendoTutorial.ini build\%ARCH%\%CONFIG%\
        echo Configuration file copied.
    )
) else (
    echo Build failed with error code %ERRORLEVEL%.
)

goto end

:usage
echo Usage: build.bat [x86^|x64^|arm64] [debug^|release]
echo Examples:
echo   build.bat                  - Builds x64 release (default)
echo   build.bat x86              - Builds x86 release
echo   build.bat arm64            - Builds ARM64 release
echo   build.bat debug            - Builds x64 debug
echo   build.bat x86 debug        - Builds x86 debug

:end
endlocal
