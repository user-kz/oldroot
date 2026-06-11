#!/usr/bin/env python3
"""
fix_bugs.py — исправляет найденные баги:
  БАГ #1: pdf_report.py — неопределённая переменная SUPERVISOR
  БАГ #2: online_learner — дообучает rf_cicids, а приложение грузит rf_default/rf_rootkitguard
  БАГ #3: show_page("rootkit") — страницы нет, будет KeyError (3 места)
  БАГ #4: _toggle_nav — pages_nav ссылается на несуществующий ключ "rootkit"
"""

BASE = "/home/manasuser/rootkitguard_fresh/src"

# ════════════════════════════════════════════════════════════════
# БАГ #1 — pdf_report.py: SUPERVISOR не определён
# ════════════════════════════════════════════════════════════════
pdf = f"{BASE}/pdf_report.py"
with open(pdf, "r") as f:
    c = f.read()

if "SUPERVISOR" in c and "SUPERVISOR =" not in c:
    # Добавляем определение рядом с YEAR
    c = c.replace("YEAR = '2026'", "YEAR = '2026'\nSUPERVISOR = 'Alin G.T.'")
    with open(pdf, "w") as f:
        f.write(c)
    print("БАГ #1 ИСПРАВЛЕН: добавлен SUPERVISOR = 'Alin G.T.' в pdf_report.py")
else:
    print("БАГ #1: уже исправлен или не найден")

# ════════════════════════════════════════════════════════════════
# БАГ #3 + #4 — rootkitguard.py: ссылки на несуществующую "rootkit"
# ════════════════════════════════════════════════════════════════
rg = f"{BASE}/rootkitguard.py"
with open(rg, "r") as f:
    c = f.read()

# --- Фикс #4: _toggle_nav pages_nav (заменяем весь блок на актуальный) ---
old_nav = '''            pages_nav = [
                (t("home"),         "home"),
                (t("scan"),         "scan"),
                (t("rootkit_scan"), "rootkit"),
                (t("monitor"),      "monitor"),
                (t("analytics"),    "analytics"),
                (t("report"),       "report"),
                (t("settings"),     "settings"),
                (t("about"),        "about"),
            ]
            icons = ["🏠","🔍","🦠","👁","📊","📄","⚙️","ℹ️"]'''
new_nav = '''            pages_nav = [
                (t("home"),          "home"),
                ("Defense Console",  "console"),
                ("Rootkit Defense",  "rkdefense"),
                (t("scan"),          "scan"),
                (t("monitor"),       "monitor"),
                (t("analytics"),     "analytics"),
                (t("report"),        "report"),
                (t("settings"),      "settings"),
                (t("about"),         "about"),
            ]
            icons = ["🏠","💻","🛡","🔍","👁","📊","📄","⚙️","ℹ️"]'''
if old_nav in c:
    c = c.replace(old_nav, new_nav, 1)
    print("БАГ #4 ИСПРАВЛЕН: _toggle_nav теперь использует актуальные страницы")
else:
    print("БАГ #4: блок pages_nav не найден (возможно уже исправлен)")

# --- Фикс #3: show_page("rootkit") → show_page("rkdefense") ---
cnt = c.count('show_page("rootkit")')
if cnt:
    c = c.replace('show_page("rootkit")', 'show_page("rkdefense")')
    print(f"БАГ #3 ИСПРАВЛЕН: {cnt} обращений show_page(rootkit)->rkdefense")

# --- Фикс: кнопка home rootkit_scan_btn тоже шлёт на rootkit ---
# (уже покрыто заменой выше)

with open(rg, "w") as f:
    f.write(c)

# ════════════════════════════════════════════════════════════════
# БАГ #2 — online_learner.py: путь модели
# Приложение грузит rf_default.pkl (дефолт). Чтобы дообучение работало
# и подхватывалось, online_learner должен писать в rf_rootkitguard.pkl
# (это RKG-модель, которая для самообучения и предназначена)
# ════════════════════════════════════════════════════════════════
ol = f"{BASE}/online_learner.py"
with open(ol, "r") as f:
    c = f.read()

if 'self.rf_path     = "models/rf_cicids.pkl"' in c:
    # Грузим стартовую из rf_default (есть всегда), сохраняем в rf_rootkitguard
    c = c.replace(
        'self.rf_path     = "models/rf_cicids.pkl"',
        'self.rf_path     = "models/rf_rootkitguard.pkl"   # RKG-модель для самообучения\n        self.rf_seed_path = "models/rf_default.pkl"        # стартовая если RKG ещё нет')
    # В _load: если rf_rootkitguard нет — берём rf_default как стартовую
    old_load = '''        try:
            self.rf     = joblib.load(self.rf_path)
            self.scaler = joblib.load(self.scaler_path)
        except Exception as e:
            print(f"[OnlineLearner] Ошибка загрузки: {e}")'''
    new_load = '''        try:
            from pathlib import Path as _P
            _src = self.rf_path if _P(self.rf_path).exists() else self.rf_seed_path
            self.rf     = joblib.load(_src)
            self.scaler = joblib.load(self.scaler_path)
        except Exception as e:
            print(f"[OnlineLearner] Ошибка загрузки: {e}")'''
    if old_load in c:
        c = c.replace(old_load, new_load, 1)
    with open(ol, "w") as f:
        f.write(c)
    print("БАГ #2 ИСПРАВЛЕН: online_learner грузит rf_default как seed, пишет в rf_rootkitguard.pkl")
else:
    print("БАГ #2: путь уже изменён или не найден")

# Проверка синтаксиса всех тронутых файлов
import py_compile
ok = True
for path in [pdf, rg, ol]:
    try:
        py_compile.compile(path, doraise=True)
    except py_compile.PyCompileError as e:
        print(f"ОШИБКА СИНТАКСИСА в {path}: {e}")
        ok = False
if ok:
    print("\\nВСЕ ФАЙЛЫ: СИНТАКСИС OK")