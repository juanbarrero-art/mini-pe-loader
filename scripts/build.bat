@echo off
setlocal EnableExtensions
set "ROOT=%~dp0.."
pushd "%ROOT%"
if not exist bin mkdir bin

rem Use the current environment if cl.exe is already available.
where cl >nul 2>nul
if not errorlevel 1 goto have_cl

rem Otherwise, ask vswhere where Visual Studio lives and load vcvars64.
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" goto no_vs

set "VSPATH="
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSPATH=%%i"
if not defined VSPATH goto no_vs
if not exist "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat" goto no_vs

call "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 goto no_vs

:have_cl
echo [1/2] Compilando el loader...
cl /nologo /W4 /O2 /MT /D_CRT_SECURE_NO_WARNINGS src\miniload.c /Fe:bin\miniload.exe /Fo:bin\
if errorlevel 1 goto fail

echo [2/2] Compilando los payloads de prueba...
cl /nologo /W4 /O2 /MT /D_CRT_SECURE_NO_WARNINGS payloads\silent.c /Fe:bin\silent.exe /Fo:bin\
if errorlevel 1 goto fail
cl /nologo /W4 /O2 /MT /D_CRT_SECURE_NO_WARNINGS payloads\seh.c /Fe:bin\seh.exe /Fo:bin\
if errorlevel 1 goto fail
cl /nologo /W4 /O2 /MT /D_CRT_SECURE_NO_WARNINGS payloads\hello.c /Fe:bin\hello.exe /Fo:bin\ user32.lib
if errorlevel 1 goto fail

echo.
echo [OK] bin\miniload.exe + payloads (silent, seh, hello)
popd
exit /b 0

:no_vs
echo [ERROR] No encuentro cl.exe ni vcvars64.bat.
echo         Abre una consola "x64 Native Tools Command Prompt" y ejecuta scripts\build.bat.
popd
exit /b 1

:fail
echo.
echo [FAIL] La compilacion fallo.
popd
exit /b 1
