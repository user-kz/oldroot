@echo off
rem RootkitGuard — запуск одной командой (Windows).
rem   Двойной клик               -> GUI
rem   start_windows.bat api      -> API сервер
chcp 65001 >nul
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
    echo [!] Python не найден. Установи с https://python.org
    echo     и отметь галочку "Add Python to PATH".
    pause
    exit /b 1
)

if not exist ".venv" (
    echo [*] Первый запуск: создаю виртуальное окружение...
    python -m venv .venv
    echo [*] Устанавливаю зависимости, это может занять несколько минут...
    ".venv\Scripts\python" -m pip install --upgrade pip -q
    ".venv\Scripts\python" -m pip install -r requirements.txt
)

if "%~1"=="" (
    ".venv\Scripts\python" main.py gui
) else (
    ".venv\Scripts\python" main.py %*
)

if errorlevel 1 pause
