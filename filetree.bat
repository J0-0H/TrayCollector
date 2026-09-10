@echo off
chcp 65001 > nul
setlocal enabledelayedexpansion

:: 切换到目标目录
cd /d "%~1"

:: 定义 ANSI 颜色转义字符
set "ESC= "
for /F "tokens=1,2 delims=#" %%a in ('"prompt #$H#$E# & echo on & for %%b in (1) do rem"') do set "ESC=%%b"

:: 定义层级颜色（可以自行更换数字：91红, 92绿, 93黄, 94蓝, 95紫, 96青）
set "color0=%ESC%[96m"
set "color1=%ESC%[92m"
set "color2=%ESC%[93m"
set "color3=%ESC%[95m"
set "color4=%ESC%[94m"
set "reset=%ESC%[0m"

echo %color0%[ 根目录: %cd% ]%reset%
echo --------------------------------------------------

:: 调用核心递归函数
call :ScanDir "%cd%" 0
goto :End

:ScanDir
setlocal
set "current_dir=%~1"
set /a "level=%~2"
set /a "next_level=level + 1"

:: 根据当前层级选择颜色
if %level% gtr 4 (set "current_color=%color4%") else (set "current_color=!color%level%!")

:: 生成前面的缩进空格和前缀
set "indent="
if %level% gtr 0 (
    for /l %%i in (1,1,%level%) do set "indent=!indent!│  "
)

:: 1. 先列出当前目录下的子文件夹
for /f "delims=" %%D in ('dir /b /ad "%current_dir%" 2^>nul') do (
    echo !indent!├── %current_color%[+ %%D]%reset%
    :: 递归进入下一层
    call :ScanDir "%current_dir%\%%D" %next_level%
)

:: 2. 再列出当前目录下的文件
for /f "delims=" %%F in ('dir /b /a-d "%current_dir%" 2^>nul') do (
    echo !indent!├── %current_color%%%F%reset%
)

endlocal
exit /b

:End
echo --------------------------------------------------
pause