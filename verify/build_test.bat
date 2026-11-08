@echo off
rem 编译并运行算法验证测试
call "C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat" -arch=x64 -no_logo
cd /d "%~dp0."
cl /nologo /std:c++20 /EHsc /W4 /utf-8 test_main.cpp ..\KeyGen.cpp /Fe:test.exe bcrypt.lib
if errorlevel 1 exit /b 1
chcp 65001 >nul
test.exe
exit /b %errorlevel%
