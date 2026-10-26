@echo off
rem build32.bat SOURCE OUT.exe: a runtime helper built as x86 (the reference's own bitness), with
rem Visual Studio's x86 compiler found through vswhere. A project's CMakeLists runs it for each helper.
setlocal
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -property installationPath`) do set "VS=%%i"
if not defined VS (echo build32: no Visual Studio found & exit /b 1)
call "%VS%\VC\Auxiliary\Build\vcvars32.bat" >nul || exit /b 1
cl /nologo /O2 /MT /EHsc /W3 /DUNICODE /D_UNICODE "%~1" /Fe"%~2" /Fo"%~dpn2.obj" /link /NOLOGO ole32.lib oleaut32.lib || exit /b 1
