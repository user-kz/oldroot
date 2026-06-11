#!/usr/bin/env bash
# RootkitGuard — запуск одной командой (Linux / macOS).
#   ./start.sh            → GUI
#   ./start.sh api        → API сервер
#   ./start.sh rootkit    → rootkit-проверки
set -e
cd "$(dirname "$0")"

PY=python3
command -v "$PY" >/dev/null 2>&1 || PY=python
command -v "$PY" >/dev/null 2>&1 || { echo "[!] Python не найден. Установи python3."; exit 1; }

if [ ! -d ".venv" ]; then
    echo "[*] Первый запуск: создаю виртуальное окружение..."
    "$PY" -m venv .venv || {
        echo "[!] Не удалось создать venv. Ubuntu/Debian: sudo apt install python3-venv"
        exit 1
    }
    echo "[*] Устанавливаю зависимости (может занять несколько минут)..."
    .venv/bin/python -m pip install --upgrade pip -q
    .venv/bin/python -m pip install -r requirements.txt
fi

# tkinter не ставится через pip — проверяем отдельно
.venv/bin/python -c "import tkinter" 2>/dev/null || {
    echo "[!] Нет tkinter. Ubuntu/Debian: sudo apt install python3-tk"
    echo "    (для режимов api/scan/rootkit tkinter не нужен)"
}

if [ $# -eq 0 ]; then set -- gui; fi
exec .venv/bin/python main.py "$@"
