@echo off
rem 编译 Release x64 成品
call "C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat" -arch=x64 -no_logo
cd /d "%~dp0."
"C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe" "ZTE_STB_Tools+key-generator.vcxproj" /p:Configuration=Release /p:Platform=x64 /m /v:m /nologo
exit /b %errorlevel%
