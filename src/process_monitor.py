"""
process_monitor.py — быстрый мониторинг процессов через psutil.

ПРОИЗВОДИТЕЛЬНОСТЬ:
  • Соединения собираются ОДНИМ системным вызовом psutil.net_connections()
    за цикл (раньше proc.net_connections() дёргался на каждый процесс —
    это перечитывало все сокеты системы N раз и было главной причиной лагов).
  • Статичные данные процесса (exe, имя, пользователь, длина cmdline)
    кэшируются по PID и не перечитываются каждый цикл.
Скоринг — интерпретируемая эвристика индикаторов малвари (rkhunter/chkrootkit).
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
        self.model_loaded = False
        self._static = {}   # кэш статичных данных по PID

    def _conn_map(self):
        """Один проход по всем сокетам системы → {pid: (n_conn, max_port)}."""
        m = {}
        try:
            for c in psutil.net_connections(kind="inet"):
                if c.pid is None:
                    continue
                port = c.laddr.port if c.laddr else 0
                n, mx = m.get(c.pid, (0, 0))
                m[c.pid] = (n + 1, max(mx, port))
        except Exception:
            pass
        return m

    def _static_info(self, proc):
        """exe/username/name/cmd_len — кэшируется (не меняется за жизнь PID)."""
        pid = proc.pid
        cached = self._static.get(pid)
        if cached is not None:
            return cached
        try:
            exe = proc.exe()
        except Exception:
            exe = ""
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
        info = {
            "name": name, "username": username, "exe": exe, "cmd_len": cmd_len,
            "exe_deleted": bool(exe) and ("(deleted)" in exe or "memfd:" in exe),
            "susp_path": any(exe.startswith(d) for d in _SUSPICIOUS_DIRS),
        }
        self._static[pid] = info
        return info

    def score_process(self, f: dict):
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
        conn_map = self._conn_map()
        alive = set()
        results = []
        for proc in psutil.process_iter(["pid", "name"]):
            pid = proc.pid
            alive.add(pid)
            try:
                with proc.oneshot():
                    cpu = proc.cpu_percent(interval=0.0)
                    rss = proc.memory_info().rss / 1024 / 1024
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            st = self._static_info(proc)
            n_conn, dst_port = conn_map.get(pid, (0, 0))
            f = {"pid": pid, "name": st["name"], "username": st["username"],
                 "cpu_percent": cpu, "mem_rss": rss, "n_conn": n_conn,
                 "dst_port": dst_port, "cmd_len": st["cmd_len"], "exe": st["exe"],
                 "exe_deleted": st["exe_deleted"], "susp_path": st["susp_path"]}
            score, reasons = self.score_process(f)
            results.append({**f, "score": round(score, 4),
                            "threat": self.level_of(score), "reasons": reasons,
                            "time": datetime.now().strftime("%H:%M:%S")})
        # чистим кэш от завершённых PID
        for dead in set(self._static) - alive:
            self._static.pop(dead, None)
        return sorted(results, key=lambda x: x["score"], reverse=True)

    def start_realtime(self, interval: int = _INTERVAL):
        if self.running:
            return
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
                # дробим сон, чтобы стоп срабатывал мгновенно
                for _ in range(int(max(interval, 1) * 2)):
                    if not self.running:
                        break
                    time.sleep(0.5)
        threading.Thread(target=loop, daemon=True).start()
        log.info(f"Real-time мониторинг запущен (интервал {interval}с)")

    def stop_realtime(self):
        self.running = False

    def add_callback(self, fn):
        self.callbacks.append(fn)


if __name__ == "__main__":
    m = ProcessMonitor()
    import time as _t
    t0 = _t.time(); r = m.scan_all_processes(); dt = _t.time() - t0
    print(f"Сканирование {len(r)} процессов за {dt*1000:.0f} мс\n")
    for x in r[:15]:
        print(f"{x['pid']:>6} {x['name'][:22]:<22} cpu={x['cpu_percent']:>5.1f} "
              f"conn={x['n_conn']:>3} score={x['score']:.2f} {x['threat']}")
