#!/usr/bin/env python3
"""Добавляет AI Incident Response: Claude анализирует находки, даёт команды,
повторный скан подтверждает устранение."""

PATH = "/home/manasuser/rootkitguard_fresh/src/rootkitguard.py"

with open(PATH, "r") as f:
    content = f.read()

# ════════════════════════════════════════════════════════════════
# 1. В конце _render_rkd_findings вызываем построение AI-панели
# ════════════════════════════════════════════════════════════════
# Находим конец метода _render_rkd_findings (перед _rkdefense_learn)
anchor = "    def _rkdefense_learn(self, findings: list):"
idx = content.index(anchor)

# Вставляем вызов AI-панели в конец _render_rkd_findings.
# Метод заканчивается циклом по находкам; добавим сохранение findings и вызов.
# Ищем последнюю строку _render (там идёт MITRE footer с evidence).
# Проще: добавим строку перед anchor что вызовет _render_rkd_response.

# Сохраняем findings в self для повторного использования + строим панель
inject = '''        # Сохраняем находки и строим AI-панель реагирования
        self._rkd_last_findings = findings
        if findings:
            self._render_rkd_response(findings, threat)

'''
content = content[:idx] + inject + content[idx:]

with open(PATH, "w") as f:
    f.write(content)
print("Шаг 1: вызов AI-панели добавлен в конец _render_rkd_findings")

# ════════════════════════════════════════════════════════════════
# 2. Добавляем методы AI Incident Response перед _rkdefense_learn
# ════════════════════════════════════════════════════════════════
with open(PATH, "r") as f:
    content = f.read()

methods = '''    def _render_rkd_response(self, findings: list, threat: str):
        """AI Incident Response — Claude даёт команды реагирования."""
        P = self._rkd_palette
        MONO = P["mono_font"]

        # Контейнер AI-реагирования (внизу панели находок)
        resp = ctk.CTkFrame(self.rkd_findings_frame, fg_color="#0a1322",
                            corner_radius=10, border_width=1, border_color=P["cyan"])
        resp.pack(fill="x", padx=10, pady=(10, 6))

        # Заголовок
        hdr = ctk.CTkFrame(resp, fg_color="transparent")
        hdr.pack(fill="x", padx=12, pady=(10, 4))
        ctk.CTkLabel(hdr, text="\\U0001f916  AI INCIDENT RESPONSE",
                     font=ctk.CTkFont(family=MONO, size=11, weight="bold"),
                     text_color=P["cyan"]).pack(side="left")
        ctk.CTkLabel(hdr, text="// Claude советует план реагирования",
                     font=ctk.CTkFont(family=MONO, size=9),
                     text_color=P["dim"]).pack(side="left", padx=8)

        # Кнопки управления
        btns = ctk.CTkFrame(resp, fg_color="transparent")
        btns.pack(fill="x", padx=12, pady=(0, 6))

        ask_btn = ctk.CTkButton(
            btns, text="\\U0001f9e0  Получить план от AI",
            height=34, corner_radius=8,
            fg_color=P["cyan"], hover_color="#00b8e0",
            text_color="#06090f",
            font=ctk.CTkFont(size=11, weight="bold"),
            command=lambda f=findings: threading.Thread(
                target=self._rkd_ai_response, args=(f,), daemon=True).start())
        ask_btn.pack(side="left", padx=(0, 6))

        self._rkd_copy_cmd_btn = ctk.CTkButton(
            btns, text="\\U0001f4cb Копировать команды",
            height=34, corner_radius=8,
            fg_color=P["panel_hi"], hover_color="#16233a",
            border_width=1, border_color=P["border"],
            text_color="#c7d3e3",
            font=ctk.CTkFont(family=MONO, size=10),
            command=self._rkd_copy_commands, state="disabled")
        self._rkd_copy_cmd_btn.pack(side="left", padx=(0, 6))

        verify_btn = ctk.CTkButton(
            btns, text="\\U0001f504 Проверить устранение",
            height=34, corner_radius=8,
            fg_color="#1a3a1a", hover_color="#2d6a4f",
            text_color="#5ef0a0",
            font=ctk.CTkFont(size=11, weight="bold"),
            command=lambda: threading.Thread(
                target=self._rkd_verify_remediation, daemon=True).start())
        verify_btn.pack(side="left")

        # Поле вывода AI-плана
        self._rkd_ai_box = ctk.CTkTextbox(
            resp, height=180,
            font=ctk.CTkFont(family=MONO, size=11),
            fg_color="#06090f", text_color="#c7d3e3", wrap="word")
        self._rkd_ai_box.pack(fill="x", padx=12, pady=(0, 6))
        self._rkd_ai_box.insert("end",
            "\\u2192 Нажми «Получить план от AI» — Claude проанализирует "
            "обнаруженные угрозы и даст точные команды для устранения.\\n")
        self._rkd_ai_box.configure(state="disabled")

        # Хранилище извлечённых команд
        self._rkd_extracted_cmds = []

        # Статус проверки
        self._rkd_verify_lbl = ctk.CTkLabel(
            resp, text="",
            font=ctk.CTkFont(family=MONO, size=10))
        self._rkd_verify_lbl.pack(anchor="w", padx=12, pady=(0, 10))

    def _rkd_ai_response(self, findings: list):
        """Запрашивает у Claude план реагирования по конкретным находкам."""
        P = self._rkd_palette
        try:
            import anthropic, re

            self.after(0, lambda: [
                self._rkd_ai_box.configure(state="normal"),
                self._rkd_ai_box.delete("1.0", "end"),
                self._rkd_ai_box.insert("end", "\\U0001f916 Claude анализирует угрозы...\\n"),
                self._rkd_ai_box.configure(state="disabled"),
            ])

            # Формируем детальное описание находок для Claude
            findings_desc = []
            for f in findings:
                findings_desc.append(
                    f"- [{f.severity}] {f.title}\\n"
                    f"  Метод: {f.method}\\n"
                    f"  Где: {f.where}\\n"
                    f"  MITRE: {f.mitre}\\n"
                    f"  Evidence: {f.evidence}")
            findings_text = "\\n".join(findings_desc)

            api_key = cfg.get("anthropic", {}).get("api_key", "")
            client = anthropic.Anthropic(api_key=api_key)

            prompt = f"""Ты эксперт по реагированию на инциденты Linux (Incident Response).
RootkitGuard обнаружил следующие rootkit-угрозы на системе Ubuntu (ядро 6.17):

{findings_text}

Дай ЧЁТКИЙ план реагирования по этапам Incident Response. Для КАЖДОГО этапа дай ТОЧНЫЕ bash-команды (с конкретными именами модулей/PID/портов из находок выше, не плейсхолдеры).

Формат ответа СТРОГО такой:

ЭТАП 1 — ИЗОЛЯЦИЯ
$ команда1
$ команда2

ЭТАП 2 — УСТРАНЕНИЕ
$ команда1

ЭТАП 3 — ПРОВЕРКА
$ команда1

ЭТАП 4 — ВОССТАНОВЛЕНИЕ (если нужно)
$ команда1

Каждая команда с новой строки начинается с "$ ". Между этапами объясни ОДНИМ предложением что делаем и зачем. Команды реальные, готовые к вставке в терминал. Отвечай на русском."""

            message = client.messages.create(
                model="claude-haiku-4-5-20251001",
                max_tokens=900,
                messages=[{"role": "user", "content": prompt}])
            result = message.content[0].text

            # Извлекаем команды (строки начинающиеся с $)
            cmds = re.findall(r"^\\s*\\$\\s*(.+)$", result, re.M)
            self._rkd_extracted_cmds = [c.strip() for c in cmds if c.strip()]

            self.app_log(f"AI Incident Response: получен план ({len(self._rkd_extracted_cmds)} команд)")

            self.after(0, lambda r=result: [
                self._rkd_ai_box.configure(state="normal", height=280),
                self._rkd_ai_box.delete("1.0", "end"),
                self._rkd_ai_box.insert("end", r),
                self._rkd_ai_box.configure(state="disabled"),
                self._rkd_copy_cmd_btn.configure(state="normal"),
            ])

        except Exception as e:
            self.after(0, lambda err=str(e): [
                self._rkd_ai_box.configure(state="normal"),
                self._rkd_ai_box.delete("1.0", "end"),
                self._rkd_ai_box.insert("end", f"[!] Ошибка AI: {err}\\n\\n"
                    "Проверь что API-ключ задан в config.yaml и API запущен."),
                self._rkd_ai_box.configure(state="disabled"),
            ])

    def _rkd_copy_commands(self):
        """Копирует извлечённые команды в буфер."""
        P = self._rkd_palette
        if not self._rkd_extracted_cmds:
            return
        text = "\\n".join(self._rkd_extracted_cmds)
        try:
            self.clipboard_clear()
            self.clipboard_append(text)
            self.update()
            self._rkd_copy_cmd_btn.configure(text="\\u2713 Скопировано!")
            self.after(2000, lambda: self._rkd_copy_cmd_btn.configure(
                text="\\U0001f4cb Копировать команды"))
            self.app_log(f"Скопировано {len(self._rkd_extracted_cmds)} команд реагирования")
        except Exception:
            pass

    def _rkd_verify_remediation(self):
        """Повторный скан для проверки что rootkit устранён."""
        P = self._rkd_palette
        from rootkit_detector import RootkitDetector

        # Запоминаем сколько было находок ДО
        before = len(getattr(self, "_rkd_last_findings", []))

        self.after(0, lambda: [
            self._rkd_verify_lbl.configure(
                text="\\U0001f504 повторное сканирование...", text_color=P["amber"]),
        ])

        try:
            det = RootkitDetector()
            result = det.full_scan()
            after = result["total"]
            score = result["score"]
            threat = result["threat"]

            self.app_log(f"ПРОВЕРКА УСТРАНЕНИЯ: было {before} находок, стало {after}, score {score}")

            if after == 0:
                msg = f"\\u2713 УСТРАНЕНО! Было {before} угроз \\u2192 стало 0. Score: {score}/100. Система чиста."
                color = P["cyan"]
            elif after < before:
                msg = f"\\u26a0 Частично: было {before} \\u2192 стало {after}. Score: {score}. Остались угрозы."
                color = P["amber"]
            else:
                msg = f"\\u2717 Не устранено: {after} угроз остаётся. Score: {score}. Выполни команды AI."
                color = P["red"]

            # Если устранено — перезапускаем полный скан чтобы обновить весь UI
            self.after(0, lambda m=msg, c=color: self._rkd_verify_lbl.configure(text=m, text_color=c))
            self.after(800, lambda: threading.Thread(
                target=self._run_rkdefense_scan, daemon=True).start())

        except Exception as e:
            self.after(0, lambda err=str(e): self._rkd_verify_lbl.configure(
                text=f"[!] Ошибка проверки: {err[:50]}", text_color=P["red"]))

'''
anchor = "    def _rkdefense_learn(self, findings: list):"
idx = content.index(anchor)
content = content[:idx] + methods + content[idx:]

with open(PATH, "w") as f:
    f.write(content)
print("Шаг 2: методы AI Incident Response добавлены")

import py_compile
try:
    py_compile.compile(PATH, doraise=True)
    print("СИНТАКСИС OK")
except py_compile.PyCompileError as e:
    print(f"ОШИБКА: {e}")