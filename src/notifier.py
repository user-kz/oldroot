"""
notifier.py — десктопные уведомления (кроссплатформенно).
Linux: notify-send (libnotify) · macOS: osascript · Windows: PowerShell balloon.
Вызывается при СРЕДНЕЙ / ВЫСОКОЙ угрозе автоматически.
"""
import sys
import subprocess
from pathlib import Path

try:
    from logger import get_logger
except ImportError:
    import logging
    def get_logger(n): return logging.getLogger(n)

log = get_logger("notifier")

ICON_PATH = str(Path(__file__).parent.parent / "assets" / "icon.png")


def _notify_linux(title: str, body: str, urgency: str) -> bool:
    icon = ICON_PATH if Path(ICON_PATH).exists() else "dialog-warning"
    subprocess.run(
        ["notify-send", "--urgency", urgency, "--icon", icon, title, body],
        timeout=5, check=True, capture_output=True
    )
    return True


def _notify_macos(title: str, body: str) -> bool:
    t = title.replace('"', "'")
    b = body.replace('"', "'")
    subprocess.run(
        ["osascript", "-e", f'display notification "{b}" with title "{t}"'],
        timeout=5, check=True, capture_output=True
    )
    return True


def _notify_windows(title: str, body: str) -> bool:
    t = title.replace("'", "''")
    b = body.replace("'", "''")
    ps = (
        "[reflection.assembly]::LoadWithPartialName('System.Windows.Forms')|Out-Null;"
        "[reflection.assembly]::LoadWithPartialName('System.Drawing')|Out-Null;"
        "$n=New-Object System.Windows.Forms.NotifyIcon;"
        "$n.Icon=[System.Drawing.SystemIcons]::Warning;"
        "$n.Visible=$true;"
        f"$n.ShowBalloonTip(5000,'{t}','{b}','Warning');"
        "Start-Sleep -Seconds 6;$n.Dispose()"
    )
    subprocess.Popen(
        ["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps],
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
    )
    return True


def notify(title: str, body: str, urgency: str = "normal") -> bool:
    """Отправить десктопное уведомление. Возвращает True если успешно."""
    try:
        if sys.platform.startswith("linux"):
            return _notify_linux(title, body, urgency)
        elif sys.platform == "darwin":
            return _notify_macos(title, body)
        elif sys.platform == "win32":
            return _notify_windows(title, body)
        log.debug(f"Уведомления не поддерживаются на {sys.platform}")
        return False
    except FileNotFoundError:
        log.debug("Утилита уведомлений не найдена (Linux: sudo apt install libnotify-bin)")
        return False
    except subprocess.CalledProcessError as e:
        log.debug(f"Ошибка утилиты уведомлений: {e}")
        return False
    except Exception as e:
        log.debug(f"Ошибка уведомления: {e}")
        return False


def notify_threat(threat_level: str, details: str = "") -> None:
    """Отправить уведомление об угрозе в зависимости от уровня."""
    config_min = "СРЕДНЯЯ"
    try:
        from config_loader import cfg
        config_min = cfg.get("notifications", {}).get("min_threat_lvl", "СРЕДНЯЯ")
        if not cfg.get("notifications", {}).get("enabled", True):
            return
    except Exception:
        pass

    order = {"НИЗКАЯ": 0, "СРЕДНЯЯ": 1, "ВЫСОКАЯ": 2}
    if order.get(threat_level, 0) < order.get(config_min, 1):
        return

    urgency_map = {"НИЗКАЯ": "low", "СРЕДНЯЯ": "normal", "ВЫСОКАЯ": "critical"}
    urgency = urgency_map.get(threat_level, "normal")

    title = f"⚠ RootkitGuard — угроза: {threat_level}"
    body  = details[:200] if details else "Обнаружена подозрительная активность"

    notify(title, body, urgency)
