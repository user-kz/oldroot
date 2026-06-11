#!/usr/bin/env python3
"""Добавляет глобальный журнал событий + кнопку 'Копировать всё' в RootkitGuard."""

PATH = "/home/manasuser/rootkitguard_fresh/src/rootkitguard.py"

with open(PATH, "r") as f:
    content = f.read()

# ── 1. Инициализация журнала в __init__ ──────────────────────────
# Добавляем self._app_log после super().__init__()
init_marker = '        self.username = username'
init_add = '''        self.username = username
        self._app_log = []  # глобальный журнал всех событий приложения'''
if 'self._app_log = []' not in content:
    content = content.replace(init_marker, init_add, 1)

# ── 2. Метод логирования + копирования ───────────────────────────
# Вставляем методы перед _build_ui
methods = '''
    def app_log(self, msg: str):
        """Записывает событие в глобальный журнал приложения."""
        from datetime import datetime
        ts = datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] {msg}"
        self._app_log.append(line)
        # Ограничиваем размер журнала
        if len(self._app_log) > 2000:
            self._app_log = self._app_log[-2000:]

    def _copy_all_log(self):
        """Копирует весь журнал приложения в буфер обмена."""
        from datetime import datetime
        header = [
            "=" * 60,
            "ROOTKITGUARD v2.1 — ПОЛНЫЙ ЖУРНАЛ ПРИЛОЖЕНИЯ",
            f"Экспортировано: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Пользователь: {self.username}",
            f"Модель: {getattr(self, 'current_model_name', 'RF')}",
            "=" * 60,
            "",
        ]
        # Добавляем последний rootkit-скан если был
        full = header + self._app_log

        # Добавляем детальные находки rootkit если есть
        if hasattr(self, "_last_rkd_report") and self._last_rkd_report:
            full += ["", "=" * 60, "ПОСЛЕДНИЙ ROOTKIT-СКАН (детально):", "=" * 60]
            full += self._last_rkd_report

        text = "\\n".join(full)
        try:
            self.clipboard_clear()
            self.clipboard_append(text)
            self.update()
            if hasattr(self, "_copy_btn"):
                self._copy_btn.configure(text="\\u2713 Скопировано!")
                self.after(2000, lambda: self._copy_btn.configure(
                    text="\\U0001f4cb Копировать всё"))
        except Exception as e:
            print(f"Ошибка копирования: {e}")

'''
if 'def _copy_all_log' not in content:
    content = content.replace('    def _build_ui(self):', methods + '    def _build_ui(self):', 1)

# ── 3. Кнопка в боковой панели ───────────────────────────────────
# Вставляем кнопку после создания model_row (статус модели)
btn_marker = '        self.learn_lbl.pack(side="right")'
btn_add = '''        self.learn_lbl.pack(side="right")

        # Кнопка "Копировать всё" — глобальный журнал
        self._copy_btn = ctk.CTkButton(
            self.nav, text="\\U0001f4cb Копировать всё",
            height=30, corner_radius=8,
            fg_color="#1e293b", hover_color="#2d3748",
            font=ctk.CTkFont(size=11),
            command=self._copy_all_log)
        self._copy_btn.pack(side="bottom", fill="x", padx=8, pady=(4, 4))'''
if '_copy_btn = ctk.CTkButton' not in content:
    content = content.replace(btn_marker, btn_add, 1)

with open(PATH, "w") as f:
    f.write(content)

print("Готово: добавлен app_log(), _copy_all_log(), кнопка 'Копировать всё'")

# ── 4. Заставляем rootkit-скан сохранять текстовый отчёт ─────────
with open(PATH, "r") as f:
    content = f.read()

# В _render_rkd_findings добавляем накопление текста
# Находим начало метода и добавляем сбор отчёта
old_render = '''    def _render_rkd_findings(self, findings: list, threat: str):
        """Рисует детальные карточки находок."""
        for w in self.rkd_findings_frame.winfo_children():
            w.destroy()'''

new_render = '''    def _render_rkd_findings(self, findings: list, threat: str):
        """Рисует детальные карточки находок."""
        # Сохраняем текстовый отчёт для копирования
        rep = [f"Угроза: {threat} | Находок: {len(findings)}", ""]
        for f in findings:
            rep.append(f"[{f.severity}] {f.title}")
            rep.append(f"  Метод: {f.method}")
            rep.append(f"  ГДЕ: {f.where}")
            rep.append(f"  КАК: {f.how}")
            rep.append(f"  ПОЧЕМУ: {f.why}")
            rep.append(f"  УСТРАНЕНИЕ: {f.fix}")
            rep.append(f"  MITRE: {f.mitre}")
            if f.evidence:
                rep.append(f"  EVIDENCE: {f.evidence}")
            rep.append("")
        self._last_rkd_report = rep
        self.app_log(f"ROOTKIT-СКАН: {threat}, находок {len(findings)}")
        for f in findings:
            self.app_log(f"  [{f.severity}] {f.title} @ {f.where}")

        for w in self.rkd_findings_frame.winfo_children():
            w.destroy()'''

if old_render in content:
    content = content.replace(old_render, new_render, 1)
    with open(PATH, "w") as f:
        f.write(content)
    print("Готово: rootkit-скан теперь пишет детальный отчёт в журнал")
else:
    print("ВНИМАНИЕ: метод _render_rkd_findings не найден в ожидаемом виде")