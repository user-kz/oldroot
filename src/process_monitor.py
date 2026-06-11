"""
process_monitor.py — мониторинг процессов через psutil.

Скоринг основан на интерпретируемых индикаторах вредоносного ПО
(а НЕ на сетевой ML-модели CIC-IDS, которая раньше давала ложные «ВЫСОКАЯ»
на каждый процесс). Индикаторы — из практик rkhunter / chkrootkit:
запуск из /tmp, удалённый/безфайловый бинарь (memfd), подозрительные порты,
маскировка под системный поток, аномальная активность.
"""
import psutil
import threading
import time
from datetime import datetime

try:
    from logger import get_logger
    from config_loader import cfg
    _INTERVAL = cfg.get("monitor", {}).get("interval_sec", 3)
    _SUSP_PORTS = set(cfg.get("monitor", {}).get("suspicious_ports", [4444, 1337, 31337]))
except Exception:
    import logging
    def get_logger(n): return logging.getLogger(n)
    _INTERVAL   = 3
    _SUSP_PORTS = {4444, 1337, 31337, 6666, 9999}

log = get_logger("process_monitor")

_SUSPICIOUS_DIRS = ("/tmp/", "/dev/shm/", "/var/tmp/", "/run/shm/")
_MASQUERADE = {"kworker", "kthreadd", "ksoftirqd", "migration", "systemd", "kswapd"}


class ProcessMonitor:
    def __init__(self, model_path: str = "models/rf_cicids.pkl",
                 scaler_path: str = "models/scaler_cicids.pkl"):
        self.running   = False
        self.results   = []
        self.callbacks = []
        self.model_loaded = False  # сетевая ML тут намеренно не используется

    def get_process_features(self, proc) -> dict:
        try:
            with proc.oneshot():
                cpu = proc.cpu_percent(interval=0.0)
                mem = proc.memory_info()
                try:
                    try:
                        connections = proc.net_connections()
                    except AttributeError:
                        connections = proc.connections()
                    n_conn = len(connections)
                    ports  = [c.laddr.port for c in connections if c.laddr] or [0]
                    dst_port = max(ports)
                except Exception:
                    n_conn, dst_port = 0, 0
                try:
                    exe = proc.exe()
                except Exception:
                    exe = ""
                exe_deleted = bool(exe) and ("(deleted)" in exe or "memfd:" in exe)
                susp_path   = any(exe.startswith(d) for d in _SUSPICIOUS_DIRS)
                try:
                    name = proc.name()
                except Exception:
                    name = "?"
                try:
                    username = proc.username()
                except Exception:
                    username = "?"
                try:
                    cmd_len = len(" ".join(proc.cmdline()))
                except Exception:
                    cmd_len = 0
                return {
                    "pid": proc.pid, "name": name, "username": username,
                    "cpu_percent": cpu, "mem_rss": mem.rss / 1024 / 1024,
                    "n_conn": n_conn, "dst_port": dst_port, "cmd_len": cmd_len,
                    "exe": exe, "exe_deleted": exe_deleted, "susp_path": susp_path,
                }
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None

    def score_process(self, f: dict):
        """Возвращает (score 0..1, list[str] причин). Норм. процессы → ~0."""
        score, reasons = 0.0, []
        if f["exe_deleted"]:
            score += 0.55; reasons.append("безфайловый/удалённый бинарь")
        if f["susp_path"]:
            score += 0.45; reasons.append(f"запуск из {f['exe']}")
        if f["dst_port"] in _SUSP_PORTS:
            score += 0.40; reasons.append(f"подозрительный порт {f['dst_port']}")
        base = f["name"].lstrip("[").split("/")[0].rstrip("]0123456789")
        if base in _MASQUERADE and f["exe"] and not f["exe"].startswith(("/usr", "/sbin", "/lib", "/bin")):
            score += 0.50; reasons.append(f"маскировка под «{base}»")
        if f["n_conn"] > 50:
            score += 0.20; reasons.append(f"много соединений ({f['n_conn']})")
        if f["cpu_percent"] > 85:
            score += 0.10; reasons.append("высокая загрузка CPU")
        if f["cmd_len"] > 300:
            score += 0.10; reasons.append("длинная командная строка")
        return min(score, 1.0), reasons

    @staticmethod
    def level_of(score: float) -> str:
        return ("ВЫСОКАЯ" if score >= 0.6 else
                "СРЕДНЯЯ" if score >= 0.35 else "НИЗКАЯ")

    def scan_all_processes(self) -> list:
        results = []
        for proc in psutil.process_iter(["pid", "name"]):
            f = self.get_process_features(proc)
            if f is None:
                continue
            score, reasons = self.score_process(f)
            results.append({**f, "score": round(score, 4),
                            "threat": self.level_of(score), "reasons": reasons,
                            "time": datetime.now().strftime("%H:%M:%S")})
        return sorted(results, key=lambda x: x["score"], reverse=True)

    def start_realtime(self, interval: int = _INTERVAL):
        self.running = True
        def loop():
            try:
                self.scan_all_processes()  # прогрев cpu_percent
            except Exception:
                pass
            while self.running:
                try:
                    results = self.scan_all_processes()
                    self.results = results
                    for cb in self.callbacks:
                        try:
                            cb(results)
                        except Exception as e:
                            log.error(f"Callback ошибка: {e}")
                except Exception as e:
                    log.error(f"Monitor loop ошибка: {e}")
                time.sleep(interval)
        threading.Thread(target=loop, daemon=True).start()
        log.info(f"Real-time мониторинг запущен (интервал {interval}с)")

    def stop_realtime(self):
        self.running = False
        log.info("Мониторинг остановлен")

    def add_callback(self, fn):
        self.callbacks.append(fn)


if __name__ == "__main__":
    monitor = ProcessMonitor()
    print("Сканирование процессов...\n")
    results = monitor.scan_all_processes()
    print(f"{'PID':>6} {'Имя':<22} {'CPU%':>6} {'RAM MB':>8} {'Conn':>5} {'Score':>7} {'Угроза'}")
    print("-" * 72)
    for r in results[:20]:
        print(f"{r['pid']:>6} {r['name'][:22]:<22} {r['cpu_percent']:>6.1f} "
              f"{r['mem_rss']:>8.1f} {r['n_conn']:>5} {r['score']:>7.4f} {r['threat']}")
