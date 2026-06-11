"""
rootkit_detector.py — Rootkit Detection Engine для RootkitGuard v2.1
Обнаруживает rootkit-подобную активность на Linux системе.

Методы обнаружения:
  1. Hidden Processes  — сравнение /proc с ps
  2. Hidden Modules    — сравнение /proc/modules с /sys/module
  3. Privilege Esc     — процессы с UID=0 запущенные не от root
  4. Syscall/Binary    — проверка целостности критичных бинарников
  5. Baseline (DNA)    — сравнение со снимком чистой системы

Каждая находка содержит: где, как, почему опасно, что делать, MITRE ATT&CK.
"""
import os
import re
import json
import hashlib
import subprocess
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import List


# ── Структура находки ────────────────────────────────────────────
@dataclass
class Finding:
    method:      str          # каким методом обнаружено
    severity:    str          # ВЫСОКАЯ / СРЕДНЯЯ / НИЗКАЯ
    title:       str          # краткое название
    where:       str          # где именно (PID, путь, имя)
    how:         str          # как обнаружено (техническое описание)
    why:         str          # почему опасно
    fix:         str          # команда устранения
    mitre:       str          # MITRE ATT&CK техника
    evidence:    str = ""      # сырые данные-доказательство

    def to_dict(self):
        return asdict(self)


# ── Главный детектор ─────────────────────────────────────────────
class RootkitDetector:

    BASELINE_PATH = "data/rootkit_baseline.json"

    # Критичные бинарники которые rootkit часто подменяет
    CRITICAL_BINS = [
        "/bin/ps", "/usr/bin/ps",
        "/bin/ls", "/usr/bin/ls",
        "/bin/netstat", "/usr/bin/netstat",
        "/bin/ss", "/usr/bin/ss",
        "/bin/lsmod", "/usr/bin/lsmod",
        "/usr/bin/top", "/bin/login",
        "/usr/bin/sshd", "/usr/sbin/sshd",
    ]

    # Известные имена rootkit модулей/процессов
    KNOWN_ROOTKIT_NAMES = [
        "diamorphine", "reptile", "adore", "knark", "modhide",
        "rkit", "suterusu", "kbeast", "enyelkm", "wkmr",
        "singularity", "pumakit", "puma", "kitsune",
    ]

    def __init__(self):
        Path("data").mkdir(exist_ok=True)

    # ── Утилиты ──────────────────────────────────────────────────
    def _run(self, cmd: list) -> str:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return r.stdout
        except Exception:
            return ""

    def _file_hash(self, path: str) -> str:
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                while chunk := f.read(8192):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ""

    # ── МЕТОД 1: Скрытые процессы ────────────────────────────────
    def detect_hidden_processes(self) -> List[Finding]:
        """Сравниваем PID в /proc с тем что показывает ps.
        Если PID есть в /proc но нет в ps — процесс скрыт rootkit."""
        findings = []
        try:
            # PID из /proc (реальные)
            proc_pids = set()
            for entry in os.listdir("/proc"):
                if entry.isdigit():
                    proc_pids.add(int(entry))

            # PID из ps (которые видны)
            ps_out = self._run(["ps", "-eo", "pid", "--no-headers"])
            ps_pids = set()
            for line in ps_out.strip().split("\n"):
                line = line.strip()
                if line.isdigit():
                    ps_pids.add(int(line))

            # Процессы которые есть в /proc но скрыты от ps
            hidden = proc_pids - ps_pids
            # Фильтруем — ядерные потоки и короткоживущие могут давать ложные
            real_hidden = []
            for pid in hidden:
                try:
                    # Проверяем что процесс реально существует и имеет cmdline
                    cmdline_path = f"/proc/{pid}/cmdline"
                    if os.path.exists(cmdline_path):
                        with open(cmdline_path, "rb") as f:
                            cmdline = f.read().replace(b"\x00", b" ").decode(errors="ignore").strip()
                        comm_path = f"/proc/{pid}/comm"
                        comm = ""
                        if os.path.exists(comm_path):
                            comm = Path(comm_path).read_text(errors="ignore").strip()
                        # Если есть cmdline — это пользовательский процесс, не ядерный поток
                        if cmdline:
                            real_hidden.append((pid, comm, cmdline))
                except Exception:
                    continue

            for pid, comm, cmdline in real_hidden:
                findings.append(Finding(
                    method   = "Hidden Process Detection",
                    severity = "ВЫСОКАЯ",
                    title    = f"Скрытый процесс PID {pid}",
                    where    = f"PID {pid} ({comm}) — /proc/{pid}",
                    how      = (f"Процесс присутствует в /proc/{pid}, но НЕ виден в выводе "
                                f"команды ps. Классический признак rootkit, который "
                                f"перехватывает системные вызовы для скрытия процессов."),
                    why      = ("Rootkit скрывает вредоносный процесс (backdoor, майнер, "
                                "кейлоггер) от стандартных инструментов мониторинга. "
                                "Администратор не видит угрозу через ps/top/htop."),
                    fix      = f"sudo kill -9 {pid}  # завершить процесс\\nsudo ls -la /proc/{pid}/exe  # найти бинарник",
                    mitre    = "T1014 (Rootkit), T1564.001 (Hidden Files)",
                    evidence = f"cmdline: {cmdline[:200]}"
                ))
        except Exception as e:
            findings.append(Finding(
                method="Hidden Process Detection", severity="НИЗКАЯ",
                title="Ошибка проверки", where="—",
                how=f"Не удалось выполнить проверку: {e}",
                why="—", fix="—", mitre="—"))
        return findings

    # ── МЕТОД 2: Скрытые модули ядра ─────────────────────────────
    def detect_hidden_modules(self) -> List[Finding]:
        """Сравниваем /proc/modules с /sys/module.
        LKM rootkit удаляет себя из /proc/modules но остаётся в /sys/module."""
        findings = []
        try:
            # Модули из /proc/modules (lsmod читает отсюда)
            proc_modules = set()
            try:
                with open("/proc/modules") as f:
                    for line in f:
                        name = line.split()[0]
                        proc_modules.add(name)
            except Exception:
                pass

            # Модули из /sys/module (реальные загруженные)
            sys_modules = set()
            try:
                for entry in os.listdir("/sys/module"):
                    # Только модули с секцией (реально загруженные LKM)
                    if os.path.exists(f"/sys/module/{entry}/sections"):
                        sys_modules.add(entry)
            except Exception:
                pass

            # Модули в /sys но скрытые из /proc
            hidden_modules = sys_modules - proc_modules

            for mod in hidden_modules:
                is_known = any(rk in mod.lower() for rk in self.KNOWN_ROOTKIT_NAMES)
                findings.append(Finding(
                    method   = "Hidden Kernel Module Detection",
                    severity = "ВЫСОКАЯ",
                    title    = f"Скрытый модуль ядра: {mod}" + (" [ИЗВЕСТНЫЙ ROOTKIT]" if is_known else ""),
                    where    = f"/sys/module/{mod} (отсутствует в /proc/modules)",
                    how      = (f"Модуль '{mod}' присутствует в /sys/module/, но скрыт "
                                f"из /proc/modules (откуда читает lsmod). LKM rootkit "
                                f"удаляет себя из списка модулей через list_del()."),
                    why      = ("Загружаемый модуль ядра (LKM) с правами kernel-уровня может "
                                "перехватывать любые системные вызовы, скрывать процессы, "
                                "файлы, давать root-доступ. Самая опасная категория rootkit."),
                    fix      = f"sudo rmmod {mod}  # выгрузить модуль\\nsudo cat /sys/module/{mod}/sections/.text  # адрес в памяти",
                    mitre    = "T1547.006 (Kernel Modules), T1014 (Rootkit)",
                    evidence = f"Модуль найден в /sys/module/{mod}"
                ))

            # Проверка известных rootkit по имени в /sys/module
            for entry in sys_modules:
                if any(rk in entry.lower() for rk in self.KNOWN_ROOTKIT_NAMES):
                    if entry not in hidden_modules:  # не дублируем
                        findings.append(Finding(
                            method   = "Known Rootkit Signature",
                            severity = "ВЫСОКАЯ",
                            title    = f"Известный rootkit: {entry}",
                            where    = f"/sys/module/{entry}",
                            how      = f"Имя модуля '{entry}' совпадает с базой известных rootkit.",
                            why      = "Обнаружен модуль с именем известного публичного rootkit.",
                            fix      = f"sudo rmmod {entry}",
                            mitre    = "T1547.006 (Kernel Modules)",
                            evidence = f"Совпадение по сигнатуре имени"
                        ))
        except Exception as e:
            findings.append(Finding(
                method="Hidden Kernel Module Detection", severity="НИЗКАЯ",
                title="Ошибка проверки", where="—",
                how=f"{e}", why="—", fix="—", mitre="—"))
        return findings

    # ── МЕТОД 3: Privilege Escalation ────────────────────────────
    def detect_privilege_escalation(self) -> List[Finding]:
        """Ищем процессы с EUID=0 (root) которые запущены от обычного
        пользователя (RUID != 0). Признак privilege escalation."""
        findings = []
        try:
            for entry in os.listdir("/proc"):
                if not entry.isdigit():
                    continue
                pid = entry
                status_path = f"/proc/{pid}/status"
                if not os.path.exists(status_path):
                    continue
                try:
                    content = Path(status_path).read_text(errors="ignore")
                    # Uid: real effective saved filesystem
                    uid_match = re.search(r"^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)", content, re.M)
                    name_match = re.search(r"^Name:\s+(.+)", content, re.M)
                    if not uid_match:
                        continue
                    ruid = int(uid_match.group(1))
                    euid = int(uid_match.group(2))
                    suid = int(uid_match.group(3))
                    pname = name_match.group(1) if name_match else "?"

                    # RUID != 0 но EUID == 0 — повышение привилегий
                    # Исключаем легитимные setuid бинарники (sudo, su, passwd, polkit)
                    legit = {"sudo", "su", "passwd", "polkitd", "pkexec",
                             "gpasswd", "chsh", "chfn", "newgrp", "mount",
                             "umount", "ping", "fusermount", "fusermount3", "dbus-daemon",
                     "snapd", "snap-confine", "ntfs-3g", "pkexec", "at",
                             "systemd", "agetty", "login", "sshd", "cron"}
                    if ruid != 0 and euid == 0 and pname not in legit:
                        # Получаем cmdline
                        cmdline = ""
                        try:
                            with open(f"/proc/{pid}/cmdline", "rb") as f:
                                cmdline = f.read().replace(b"\x00", b" ").decode(errors="ignore").strip()
                        except Exception:
                            pass
                        findings.append(Finding(
                            method   = "Privilege Escalation Detection",
                            severity = "ВЫСОКАЯ",
                            title    = f"Privilege Escalation: {pname} (PID {pid})",
                            where    = f"PID {pid} ({pname}) — RUID={ruid} но EUID=0",
                            how      = (f"Процесс запущен пользователем UID={ruid}, но имеет "
                                        f"эффективный UID=0 (root). Это не легитимный "
                                        f"setuid-бинарник из белого списка."),
                            why      = ("Обычный пользователь получил root-привилегии. "
                                        "Rootkit вроде Diamorphine даёт root по сигналу "
                                        "kill -64. Атакующий может полностью контролировать систему."),
                            fix      = f"sudo kill -9 {pid}  # завершить\\nsudo ls -la /proc/{pid}/exe  # найти источник",
                            mitre    = "T1548 (Abuse Elevation Control), T1068 (Privilege Escalation)",
                            evidence = f"Uid: {ruid} {euid} {suid} | cmd: {cmdline[:150]}"
                        ))
                except Exception:
                    continue
        except Exception as e:
            findings.append(Finding(
                method="Privilege Escalation Detection", severity="НИЗКАЯ",
                title="Ошибка проверки", where="—",
                how=f"{e}", why="—", fix="—", mitre="—"))
        return findings

    # ── МЕТОД 4: Целостность критичных бинарников ────────────────
    def detect_binary_tampering(self) -> List[Finding]:
        """Проверяем хеши критичных бинарников против baseline.
        Если ps/ls/netstat изменены — rootkit подменил их."""
        findings = []
        baseline = self._load_baseline()
        baseline_bins = baseline.get("binaries", {})

        for binpath in self.CRITICAL_BINS:
            if not os.path.exists(binpath):
                continue
            current_hash = self._file_hash(binpath)
            if not current_hash:
                continue

            if binpath in baseline_bins:
                old_hash = baseline_bins[binpath]
                if old_hash != current_hash:
                    findings.append(Finding(
                        method   = "Binary Integrity Check",
                        severity = "ВЫСОКАЯ",
                        title    = f"Изменён системный бинарник: {binpath}",
                        where    = binpath,
                        how      = (f"SHA-256 хеш файла изменился относительно baseline.\\n"
                                    f"Было:  {old_hash[:32]}...\\n"
                                    f"Стало: {current_hash[:32]}..."),
                        why      = (f"Системная утилита {os.path.basename(binpath)} была "
                                    f"подменена. Userland-rootkit заменяет ps/ls/netstat "
                                    f"на троянские версии, скрывающие свою активность."),
                        fix      = f"sudo apt install --reinstall coreutils  # переустановить\\nsha256sum {binpath}",
                        mitre    = "T1014 (Rootkit), T1554 (Compromise Host Software)",
                        evidence = f"old={old_hash[:16]} new={current_hash[:16]}"
                    ))
        return findings

    # ── МЕТОД 5: Подозрительные сетевые соединения ───────────────
    def detect_suspicious_connections(self) -> List[Finding]:
        """Ищем backdoor порты и сравниваем ss с /proc/net/tcp."""
        findings = []
        backdoor_ports = {4444, 6666, 6667, 31337, 1337, 12345, 5555, 2323}
        try:
            ss_out = self._run(["ss", "-tlnp"])
            for line in ss_out.strip().split("\n")[1:]:
                m = re.search(r":(\d+)\s", line)
                if m:
                    port = int(m.group(1))
                    if port in backdoor_ports:
                        findings.append(Finding(
                            method   = "Suspicious Connection Detection",
                            severity = "ВЫСОКАЯ",
                            title    = f"Backdoor порт открыт: {port}",
                            where    = f"TCP порт {port} (LISTEN)",
                            how      = f"Обнаружен слушающий сокет на порту {port} — известный backdoor-порт.",
                            why      = ("Порт используется backdoor/reverse-shell. "
                                        "Атакующий может удалённо подключиться к системе."),
                            fix      = f"sudo ss -tlnp | grep :{port}\\nsudo iptables -A INPUT -p tcp --dport {port} -j DROP",
                            mitre    = "T1571 (Non-Standard Port), T1059 (Command Execution)",
                            evidence = line.strip()[:150]
                        ))
        except Exception:
            pass
        return findings

    # ── Baseline (System DNA) ────────────────────────────────────
    def create_baseline(self) -> dict:
        """Снимаем отпечаток чистой системы."""
        baseline = {
            "created":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "binaries": {},
            "modules":  [],
        }
        for binpath in self.CRITICAL_BINS:
            if os.path.exists(binpath):
                h = self._file_hash(binpath)
                if h:
                    baseline["binaries"][binpath] = h
        try:
            with open("/proc/modules") as f:
                baseline["modules"] = sorted([l.split()[0] for l in f])
        except Exception:
            pass
        Path(self.BASELINE_PATH).write_text(
            json.dumps(baseline, ensure_ascii=False, indent=2))
        return baseline

    def _load_baseline(self) -> dict:
        if Path(self.BASELINE_PATH).exists():
            try:
                return json.loads(Path(self.BASELINE_PATH).read_text())
            except Exception:
                pass
        return {}

    def has_baseline(self) -> bool:
        return Path(self.BASELINE_PATH).exists()

    # ── Полное сканирование ──────────────────────────────────────
    def full_scan(self) -> dict:
        """Запускает все 5 методов, возвращает результат с findings."""
        all_findings = []

        checks = [
            ("Скрытые процессы",      self.detect_hidden_processes),
            ("Скрытые модули ядра",   self.detect_hidden_modules),
            ("Privilege Escalation",  self.detect_privilege_escalation),
            ("Целостность бинарников", self.detect_binary_tampering),
            ("Backdoor соединения",   self.detect_suspicious_connections),
        ]

        check_results = {}
        for name, fn in checks:
            try:
                f = fn()
                # Убираем "ошибки проверки" из основных находок
                real = [x for x in f if x.severity != "НИЗКАЯ" or x.title != "Ошибка проверки"]
                all_findings.extend(real)
                check_results[name] = len(real)
            except Exception:
                check_results[name] = -1

        high = sum(1 for f in all_findings if f.severity == "ВЫСОКАЯ")
        med  = sum(1 for f in all_findings if f.severity == "СРЕДНЯЯ")

        # Security Score: каждая ВЫСОКАЯ -25, СРЕДНЯЯ -10
        score = max(0, 100 - high * 25 - med * 10)

        threat = ("ВЫСОКАЯ" if high > 0
                  else "СРЕДНЯЯ" if med > 0
                  else "ЧИСТАЯ")

        return {
            "timestamp":     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "score":         score,
            "threat":        threat,
            "total":         len(all_findings),
            "high":          high,
            "medium":        med,
            "check_results": check_results,
            "findings":      [f.to_dict() for f in all_findings],
            "has_baseline":  self.has_baseline(),
        }


if __name__ == "__main__":
    det = RootkitDetector()
    if not det.has_baseline():
        print("[*] Создаю baseline...")
        det.create_baseline()
    print("[*] Сканирование...")
    result = det.full_scan()
    print(f"\\nSecurity Score: {result['score']}/100")
    print(f"Угроза: {result['threat']}")
    print(f"Находок: {result['total']} (ВЫСОКАЯ: {result['high']})")
    for f in result["findings"]:
        print(f"\\n  [{f['severity']}] {f['title']}")
        print(f"    Где: {f['where']}")
        print(f"    MITRE: {f['mitre']}")