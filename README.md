# RootkitGuard v2.1

**Система обнаружения rootkit-подобных аномалий на основе машинного обучения**

МУИТ · Алматы · 2026 · Научный руководитель: Alin G.T.
Авторы: Амангелды Манас · Курманов Искандер · Куанышбек Бекарыс

---

## Быстрый старт

Нужен только [Python 3.10+](https://python.org). Зависимости поставятся сами при первом запуске.

**Windows** — двойной клик по `start_windows.bat`

**Linux / macOS:**

```bash
chmod +x start.sh
./start.sh
```

> Linux: при ошибке venv/tkinter — `sudo apt install python3-venv python3-tk`
> Ubuntu, ярлык в меню приложений: `./install.sh`

---

## Команды

| Команда | Описание |
|---|---|
| `./start.sh` / `start_windows.bat` | GUI |
| `./start.sh api` | FastAPI сервер → http://localhost:8000/docs |
| `./start.sh scan data/raw/file.csv` | Сканировать CSV |
| `./start.sh rootkit` | Rootkit-проверки системы (только Linux) |
| `./start.sh monitor` | Мониторинг процессов в консоли |

Docker (только API): `docker-compose up -d`

---

## Возможности

- **ML-сканирование трафика** — Random Forest / XGBoost, обучено на CIC-IDS2018
- **Rootkit-проверки (Linux)** — скрытые процессы (/proc vs ps), модули ядра, LD_PRELOAD, подозрительные порты, целостность системных файлов, привилегии
- **GUI** (CustomTkinter): сканирование, мониторинг, аналитика, Rootkit Defense, PDF-отчёты, настройки — 3 языка (RU/EN/KZ), экран входа
- **REST API** (FastAPI + SQLite): история сканирований, PDF-отчёты, live-статистика
- **Уведомления** на Windows / Linux / macOS при средней и высокой угрозе

## API

| Endpoint | Метод | Описание |
|---|---|---|
| `/scan` | POST | Сканировать CSV |
| `/rootkit/scan` | POST | Rootkit-проверки системы |
| `/history` | GET | История сканирований |
| `/history/{id}` | DELETE | Удалить запись |
| `/report/pdf/{id}` | GET | Скачать PDF-отчёт |
| `/report/send` | POST | Отправить отчёт |
| `/live/stats` | GET | Текущая статистика |
| `/health` | GET | Статус сервера |

---

## Структура

```
oldroot/
├── main.py                 ← точка входа (gui / api / scan / rootkit / monitor)
├── start.sh                ← запуск Linux/macOS
├── start_windows.bat       ← запуск Windows
├── install.sh              ← ярлык в меню Ubuntu
├── config/
│   └── config.example.yaml ← шаблон настроек (копируется в config.yaml)
├── src/
│   ├── rootkitguard.py     ← GUI
│   ├── api.py              ← FastAPI
│   ├── rootkit_checker.py  ← Linux rootkit-проверки
│   ├── threat_monitor.py   ← адаптивный мониторинг угроз
│   ├── process_monitor.py  ← мониторинг процессов
│   ├── live_capture.py     ← захват трафика
│   ├── pdf_report.py       ← PDF-отчёты
│   ├── train_cicids.py     ← обучение моделей
│   └── ...
├── models/                 ← rf_cicids.pkl, scaler_cicids.pkl
└── data/raw/               ← датасеты CSV
```

## Обучение моделей

```bash
# Скачай CIC-IDS2018 → data/raw/friday_traffic.csv
python3 src/train_cicids.py    # модели сохранятся в models/
```
