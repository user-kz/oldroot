#!/usr/bin/env python3
"""Редизайн _page_rkdefense (SOC + Forensic) + перенос кнопки 'Копировать всё' в страницу."""

PATH = "/home/manasuser/rootkitguard_fresh/src/rootkitguard.py"

with open(PATH, "r") as f:
    content = f.read()

# ════════════════════════════════════════════════════════════════
# 1. Убираем кнопку "Копировать всё" из боковой панели
# ════════════════════════════════════════════════════════════════
old_sidebar_btn = '''        # Кнопка "Копировать всё" — глобальный журнал
        self._copy_btn = ctk.CTkButton(
            self.nav, text="\\U0001f4cb Копировать всё",
            height=30, corner_radius=8,
            fg_color="#1e293b", hover_color="#2d3748",
            font=ctk.CTkFont(size=11),
            command=self._copy_all_log)
        self._copy_btn.pack(side="bottom", fill="x", padx=8, pady=(4, 4))

'''
content = content.replace(old_sidebar_btn, "", 1)

# ════════════════════════════════════════════════════════════════
# 2. Новая страница _page_rkdefense — SOC + Forensic дизайн
# ════════════════════════════════════════════════════════════════
# Находим старый метод (от 'def _page_rkdefense' до 'def _rkdefense_baseline')
start = content.index("    def _page_rkdefense(self):")
end = content.index("    def _rkdefense_baseline(self):")
old_method = content[start:end]

new_method = '''    def _page_rkdefense(self):
        """Страница обнаружения rootkit — SOC + Forensic дизайн."""
        # ── Цветовая палитра ──────────────────────────────────────
        C_BG       = "#06090f"   # глубокий фон
        C_PANEL    = "#0b1220"   # панели
        C_PANEL_HI = "#0f1829"   # светлее
        C_BORDER   = "#1b2638"   # границы
        C_MONO     = "#7d8da5"   # серый текст
        C_DIM      = "#3d4d63"   # тусклый
        C_CYAN     = "#00d4ff"   # акцент (чисто)
        C_RED      = "#ff3b4e"   # критично
        C_AMBER    = "#ffa726"   # средне
        C_PURPLE   = "#b06cff"   # mitre
        MONO = "JetBrains Mono"  # если нет — упадёт на системный моно

        frame = ctk.CTkFrame(self.main, fg_color="transparent")

        # ══ КОМАНДНАЯ СТРОКА СТАТУСА (SOC header) ══════════════════
        cmdbar = ctk.CTkFrame(frame, fg_color=C_BG, corner_radius=10,
                              border_width=1, border_color=C_BORDER, height=46)
        cmdbar.pack(fill="x", padx=14, pady=(8, 4))
        cmdbar.pack_propagate(False)

        # Левая часть — название модуля
        left = ctk.CTkFrame(cmdbar, fg_color="transparent")
        left.pack(side="left", padx=14)
        ctk.CTkLabel(left, text="\\u2589", font=ctk.CTkFont(size=16),
                     text_color=C_RED).pack(side="left", padx=(0, 6))
        ctk.CTkLabel(left, text="ROOTKIT DEFENSE",
                     font=ctk.CTkFont(size=14, weight="bold"),
                     text_color="#e6edf7").pack(side="left")
        ctk.CTkLabel(left, text="// LKM · PROCESS · PRIVESC · INTEGRITY",
                     font=ctk.CTkFont(family=MONO, size=9),
                     text_color=C_DIM).pack(side="left", padx=10)

        # Правая часть — индикатор статуса движка
        self.rkd_engine_lbl = ctk.CTkLabel(
            cmdbar, text="\\u25cf ENGINE READY",
            font=ctk.CTkFont(family=MONO, size=10, weight="bold"),
            text_color=C_CYAN)
        self.rkd_engine_lbl.pack(side="right", padx=14)

        # ══ ВЕРХНИЙ РЯД: Score (слева) + методы (справа) ══════════
        top = ctk.CTkFrame(frame, fg_color="transparent")
        top.pack(fill="x", padx=14, pady=(0, 4))
        top.grid_columnconfigure(0, weight=0, minsize=240)
        top.grid_columnconfigure(1, weight=1)

        # ── Левая панель: Security Score (крупный вердикт) ────────
        score_panel = ctk.CTkFrame(top, fg_color=C_PANEL, corner_radius=12,
                                    border_width=1, border_color=C_BORDER)
        score_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 4))

        ctk.CTkLabel(score_panel, text="SECURITY SCORE",
                     font=ctk.CTkFont(family=MONO, size=9, weight="bold"),
                     text_color=C_DIM).pack(anchor="w", padx=16, pady=(14, 0))

        score_row = ctk.CTkFrame(score_panel, fg_color="transparent")
        score_row.pack(anchor="w", padx=16, pady=(2, 0))
        self.rkd_score_lbl = ctk.CTkLabel(score_row, text="--",
                                           font=ctk.CTkFont(size=52, weight="bold"),
                                           text_color=C_DIM)
        self.rkd_score_lbl.pack(side="left")
        ctk.CTkLabel(score_row, text="/100",
                     font=ctk.CTkFont(size=18),
                     text_color=C_DIM).pack(side="left", anchor="s", pady=(0, 12))

        # Вердикт-бейдж
        self.rkd_verdict = ctk.CTkLabel(
            score_panel, text="ОЖИДАНИЕ",
            font=ctk.CTkFont(family=MONO, size=12, weight="bold"),
            fg_color=C_PANEL_HI, corner_radius=6,
            text_color=C_DIM, height=28)
        self.rkd_verdict.pack(fill="x", padx=16, pady=(4, 8))

        # Прогресс-бар скана
        self.rkd_progress = ctk.CTkProgressBar(
            score_panel, height=4, corner_radius=2,
            progress_color=C_CYAN, fg_color=C_PANEL_HI)
        self.rkd_progress.pack(fill="x", padx=16, pady=(0, 6))
        self.rkd_progress.set(0)

        self.rkd_status = ctk.CTkLabel(
            score_panel, text="готов к сканированию",
            font=ctk.CTkFont(family=MONO, size=9),
            text_color=C_MONO)
        self.rkd_status.pack(anchor="w", padx=16, pady=(0, 8))

        self.rkd_baseline_lbl = ctk.CTkLabel(
            score_panel, text="\\u26ac baseline: нет",
            font=ctk.CTkFont(family=MONO, size=9),
            text_color=C_DIM)
        self.rkd_baseline_lbl.pack(anchor="w", padx=16, pady=(0, 14))

        # ── Правая панель: 5 детекторов (сетка 5 колонок) ─────────
        det_panel = ctk.CTkFrame(top, fg_color="transparent")
        det_panel.grid(row=0, column=1, sticky="nsew", padx=(4, 0))
        for i in range(5):
            det_panel.grid_columnconfigure(i, weight=1)
        det_panel.grid_rowconfigure(0, weight=1)

        self._rkd_cards = []
        detectors = [
            ("HIDDEN\\nPROC",    "\\U0001f50e", "T1014"),
            ("HIDDEN\\nLKM",     "\\U0001f9e9", "T1547"),
            ("PRIV\\nESC",       "\\U0001f513", "T1548"),
            ("BINARY\\nINTEGRITY","\\U0001f4c1", "T1554"),
            ("BACKDOOR\\nPORTS", "\\U0001f50c", "T1571"),
        ]
        for i, (label, icon, tag) in enumerate(detectors):
            card = ctk.CTkFrame(det_panel, fg_color=C_PANEL, corner_radius=10,
                                border_width=1, border_color=C_BORDER)
            card.grid(row=0, column=i, padx=3, sticky="nsew")

            # Верхняя полоса-индикатор
            strip = ctk.CTkFrame(card, fg_color=C_DIM, height=3, corner_radius=0)
            strip.pack(fill="x", padx=1, pady=(1, 0))

            ctk.CTkLabel(card, text=icon,
                         font=ctk.CTkFont(size=20)).pack(pady=(12, 2))
            ctk.CTkLabel(card, text=label,
                         font=ctk.CTkFont(family=MONO, size=9, weight="bold"),
                         text_color=C_MONO, justify="center").pack()
            ctk.CTkLabel(card, text=tag,
                         font=ctk.CTkFont(family=MONO, size=8),
                         text_color=C_DIM).pack(pady=(2, 0))

            # Статус-метка (○ / ✓ / ⚠N)
            status = ctk.CTkLabel(card, text="\\u25cb",
                                  font=ctk.CTkFont(size=14),
                                  text_color=C_DIM)
            status.pack(pady=(6, 12))
            self._rkd_cards.append((card, status, strip))

        # ══ ПАНЕЛЬ ДЕЙСТВИЙ ════════════════════════════════════════
        actions = ctk.CTkFrame(frame, fg_color=C_PANEL, corner_radius=10,
                               border_width=1, border_color=C_BORDER, height=52)
        actions.pack(fill="x", padx=14, pady=(4, 4))
        actions.pack_propagate(False)

        # Сканировать (главная кнопка)
        ctk.CTkButton(actions, text="\\u25b6  СКАНИРОВАТЬ",
                      width=150, height=34, corner_radius=8,
                      fg_color=C_RED, hover_color="#d62f40",
                      text_color="#ffffff",
                      font=ctk.CTkFont(size=12, weight="bold"),
                      command=lambda: threading.Thread(
                          target=self._run_rkdefense_scan, daemon=True).start()
                      ).pack(side="left", padx=(14, 6), pady=9)

        # Baseline
        ctk.CTkButton(actions, text="\\u25c9 BASELINE",
                      width=120, height=34, corner_radius=8,
                      fg_color=C_PANEL_HI, hover_color="#16233a",
                      border_width=1, border_color=C_BORDER,
                      text_color="#c7d3e3",
                      font=ctk.CTkFont(family=MONO, size=11),
                      command=lambda: threading.Thread(
                          target=self._rkdefense_baseline, daemon=True).start()
                      ).pack(side="left", padx=(0, 6), pady=9)

        # Копировать всё (перенесено сюда!)
        self._copy_btn = ctk.CTkButton(
            actions, text="\\U0001f4cb КОПИРОВАТЬ ВСЁ",
            width=160, height=34, corner_radius=8,
            fg_color=C_PANEL_HI, hover_color="#16233a",
            border_width=1, border_color=C_CYAN,
            text_color=C_CYAN,
            font=ctk.CTkFont(family=MONO, size=11),
            command=self._copy_all_log)
        self._copy_btn.pack(side="left", padx=(0, 6), pady=9)

        # Threat-индикатор справа
        self.rkd_threat_lbl = ctk.CTkLabel(
            actions, text="",
            font=ctk.CTkFont(family=MONO, size=12, weight="bold"))
        self.rkd_threat_lbl.pack(side="right", padx=16)

        # ══ ПАНЕЛЬ НАХОДОК (инциденты) ════════════════════════════
        self.rkd_findings_frame = ctk.CTkScrollableFrame(
            frame, fg_color=C_BG, corner_radius=10,
            border_width=1, border_color=C_BORDER,
            label_text="  INCIDENT LOG // обнаруженные угрозы",
            label_font=ctk.CTkFont(family=MONO, size=10, weight="bold"),
            label_fg_color=C_PANEL)
        self.rkd_findings_frame.pack(fill="both", expand=True, padx=14, pady=(4, 10))

        # Пустое состояние
        empty = ctk.CTkFrame(self.rkd_findings_frame, fg_color="transparent")
        empty.pack(pady=30)
        ctk.CTkLabel(empty, text="\\U0001f6e1",
                     font=ctk.CTkFont(size=36)).pack()
        ctk.CTkLabel(empty,
                     text="нажмите СКАНИРОВАТЬ для проверки системы",
                     font=ctk.CTkFont(family=MONO, size=11),
                     text_color=C_DIM).pack(pady=(8, 0))

        # Сохраняем палитру для использования в рендере находок
        self._rkd_palette = {
            "bg": C_BG, "panel": C_PANEL, "panel_hi": C_PANEL_HI,
            "border": C_BORDER, "mono": C_MONO, "dim": C_DIM,
            "cyan": C_CYAN, "red": C_RED, "amber": C_AMBER,
            "purple": C_PURPLE, "mono_font": MONO,
        }

        return frame

'''
content = content[:start] + new_method + content[end:]

with open(PATH, "w") as f:
    f.write(content)

print("Шаг 1-2 готово: кнопка перенесена, страница перерисована")

# ════════════════════════════════════════════════════════════════
# 3. Обновляем _run_rkdefense_scan под новый дизайн
# ════════════════════════════════════════════════════════════════
with open(PATH, "r") as f:
    content = f.read()

start = content.index("    def _run_rkdefense_scan(self):")
end = content.index("    def _render_rkd_findings(self, findings: list, threat: str):")
old_scan = content[start:end]

new_scan = '''    def _run_rkdefense_scan(self):
        """Запускает rootkit сканирование (SOC дизайн)."""
        from rootkit_detector import RootkitDetector
        P = self._rkd_palette

        # Сброс UI
        self.after(0, lambda: [
            self.rkd_status.configure(text="сканирование...", text_color=P["amber"]),
            self.rkd_score_lbl.configure(text="..", text_color=P["amber"]),
            self.rkd_verdict.configure(text="СКАН В ПРОЦЕССЕ", text_color=P["amber"]),
            self.rkd_engine_lbl.configure(text="\\u25cf SCANNING", text_color=P["amber"]),
            self.rkd_progress.set(0),
            self.rkd_progress.configure(progress_color=P["cyan"]),
            self.rkd_threat_lbl.configure(text=""),
        ])
        for card, status, strip in self._rkd_cards:
            self.after(0, lambda c=card, s=status, st=strip: [
                c.configure(border_color=P["border"]),
                s.configure(text="\\u25cb", text_color=P["dim"]),
                st.configure(fg_color=P["dim"])])

        self.after(0, lambda: [w.destroy() for w in self.rkd_findings_frame.winfo_children()])

        try:
            det = RootkitDetector()

            if not det.has_baseline():
                self.after(0, lambda: self.rkd_baseline_lbl.configure(
                    text="\\u26a0 baseline отсутствует", text_color=P["amber"]))

            methods = [
                (0, det.detect_hidden_processes),
                (1, det.detect_hidden_modules),
                (2, det.detect_privilege_escalation),
                (3, det.detect_binary_tampering),
                (4, det.detect_suspicious_connections),
            ]
            all_findings = []
            for idx, fn in methods:
                self.after(0, lambda p=(idx+1)/5: self.rkd_progress.set(p))
                try:
                    found = fn()
                    real = [f for f in found if not (f.severity == "НИЗКАЯ" and f.title == "Ошибка проверки")]
                    all_findings.extend(real)
                    card, status, strip = self._rkd_cards[idx]
                    if real:
                        self.after(0, lambda c=card, s=status, st=strip, n=len(real): [
                            c.configure(border_color=P["red"]),
                            s.configure(text=f"\\u26a0 {n}", text_color=P["red"]),
                            st.configure(fg_color=P["red"])])
                    else:
                        self.after(0, lambda c=card, s=status, st=strip: [
                            c.configure(border_color=P["cyan"]),
                            s.configure(text="\\u2713", text_color=P["cyan"]),
                            st.configure(fg_color=P["cyan"])])
                except Exception:
                    pass

            high = sum(1 for f in all_findings if f.severity == "ВЫСОКАЯ")
            med  = sum(1 for f in all_findings if f.severity == "СРЕДНЯЯ")
            score = max(0, 100 - high * 25 - med * 10)

            if high > 0:
                threat, tcolor, verdict = "ВЫСОКАЯ", P["red"], "\\u26a0 ROOTKIT ОБНАРУЖЕН"
            elif med > 0:
                threat, tcolor, verdict = "СРЕДНЯЯ", P["amber"], "\\u26a0 ПОДОЗРЕНИЕ"
            else:
                threat, tcolor, verdict = "ЧИСТАЯ", P["cyan"], "\\u2713 СИСТЕМА ЧИСТА"

            self.after(0, lambda s=score, c=tcolor: self.rkd_score_lbl.configure(
                text=str(s), text_color=c))
            self.after(0, lambda v=verdict, c=tcolor: self.rkd_verdict.configure(
                text=v, text_color=c))
            self.after(0, lambda t=threat, c=tcolor: self.rkd_threat_lbl.configure(
                text=f"\\u25cf {t}", text_color=c))
            self.after(0, lambda c=tcolor: self.rkd_progress.configure(progress_color=c))
            self.after(0, lambda: self.rkd_status.configure(
                text="скан завершён", text_color=P["mono"]))
            self.after(0, lambda c=tcolor: self.rkd_engine_lbl.configure(
                text="\\u25cf SCAN COMPLETE", text_color=c))

            self.after(0, lambda f=all_findings, t=threat: self._render_rkd_findings(f, t))

            if all_findings:
                self._rkdefense_learn(all_findings)

        except Exception as e:
            self.after(0, lambda err=str(e): self.rkd_status.configure(
                text=f"ошибка: {err[:40]}", text_color=P["red"]))

'''
content = content[:start] + new_scan + content[end:]

with open(PATH, "w") as f:
    f.write(content)
print("Шаг 3 готово: _run_rkdefense_scan обновлён")

# ════════════════════════════════════════════════════════════════
# 4. Обновляем _render_rkd_findings под forensic-стиль инцидентов
# ════════════════════════════════════════════════════════════════
with open(PATH, "r") as f:
    content = f.read()

start = content.index("    def _render_rkd_findings(self, findings: list, threat: str):")
end = content.index("    def _rkdefense_learn(self, findings: list):")
old_render = content[start:end]

new_render = '''    def _render_rkd_findings(self, findings: list, threat: str):
        """Рисует находки как forensic-инциденты."""
        P = self._rkd_palette
        MONO = P["mono_font"]

        # Текстовый отчёт для копирования
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
            w.destroy()

        # Пустое состояние — система чиста
        if not findings:
            ok = ctk.CTkFrame(self.rkd_findings_frame, fg_color=P["panel"],
                              corner_radius=12, border_width=1, border_color=P["cyan"])
            ok.pack(fill="x", padx=10, pady=10)
            inner = ctk.CTkFrame(ok, fg_color="transparent")
            inner.pack(pady=22)
            ctk.CTkLabel(inner, text="\\u2713",
                         font=ctk.CTkFont(size=40),
                         text_color=P["cyan"]).pack()
            ctk.CTkLabel(inner, text="СИСТЕМА ЧИСТА",
                         font=ctk.CTkFont(family=MONO, size=14, weight="bold"),
                         text_color=P["cyan"]).pack(pady=(8, 2))
            ctk.CTkLabel(inner, text="rootkit не обнаружен ни одним из 5 детекторов",
                         font=ctk.CTkFont(family=MONO, size=10),
                         text_color=P["dim"]).pack()
            return

        # Карточки-инциденты
        for i, f in enumerate(findings):
            sev_color = {"ВЫСОКАЯ": P["red"], "СРЕДНЯЯ": P["amber"],
                         "НИЗКАЯ": P["mono"]}.get(f.severity, P["mono"])

            # Контейнер инцидента
            card = ctk.CTkFrame(self.rkd_findings_frame, fg_color=P["panel"],
                                corner_radius=10, border_width=1, border_color=P["border"])
            card.pack(fill="x", padx=10, pady=6)

            # Severity-полоса слева + контент
            body = ctk.CTkFrame(card, fg_color="transparent")
            body.pack(fill="x")
            sev_strip = ctk.CTkFrame(body, fg_color=sev_color, width=4, corner_radius=0)
            sev_strip.pack(side="left", fill="y", padx=(0, 0), pady=0)

            content_col = ctk.CTkFrame(body, fg_color="transparent")
            content_col.pack(side="left", fill="both", expand=True, padx=2)

            # ── Заголовок инцидента ──
            head = ctk.CTkFrame(content_col, fg_color="transparent")
            head.pack(fill="x", padx=12, pady=(10, 2))
            # ID инцидента
            ctk.CTkLabel(head, text=f"INC-{i+1:02d}",
                         font=ctk.CTkFont(family=MONO, size=9, weight="bold"),
                         fg_color=P["panel_hi"], corner_radius=4,
                         text_color=sev_color, width=54, height=20).pack(side="left", padx=(0, 8))
            ctk.CTkLabel(head, text=f.title,
                         font=ctk.CTkFont(size=12, weight="bold"),
                         text_color="#e6edf7").pack(side="left")
            # Severity бейдж справа
            ctk.CTkLabel(head, text=f.severity,
                         font=ctk.CTkFont(family=MONO, size=9, weight="bold"),
                         fg_color=sev_color, corner_radius=4,
                         text_color="#06090f", width=72, height=20).pack(side="right")

            # Метод-детектор
            ctk.CTkLabel(content_col, text=f"detector: {f.method}",
                         font=ctk.CTkFont(family=MONO, size=9),
                         text_color=P["dim"]).pack(anchor="w", padx=12, pady=(0, 6))

            # ── Технические секции (моноширинные блоки) ──
            sections = [
                ("WHERE", f.where, P["mono"]),
                ("HOW",   f.how,   P["mono"]),
                ("RISK",  f.why,   "#c7d3e3"),
            ]
            for tag, value, vcolor in sections:
                blk = ctk.CTkFrame(content_col, fg_color=P["bg"], corner_radius=6)
                blk.pack(fill="x", padx=12, pady=2)
                ctk.CTkLabel(blk, text=tag,
                             font=ctk.CTkFont(family=MONO, size=8, weight="bold"),
                             text_color=P["dim"], width=54, anchor="nw",
                             justify="left").pack(side="left", anchor="n", padx=(8, 4), pady=6)
                ctk.CTkLabel(blk, text=value,
                             font=ctk.CTkFont(family=MONO, size=10),
                             text_color=vcolor, anchor="w", justify="left",
                             wraplength=560).pack(side="left", anchor="n", fill="x",
                                                  expand=True, pady=6, padx=(0, 8))

            # ── Команда устранения (terminal-блок) ──
            fix_blk = ctk.CTkFrame(content_col, fg_color="#04130a", corner_radius=6,
                                   border_width=1, border_color="#0f3320")
            fix_blk.pack(fill="x", padx=12, pady=(4, 2))
            ctk.CTkLabel(fix_blk, text="\\u2192 REMEDIATION",
                         font=ctk.CTkFont(family=MONO, size=8, weight="bold"),
                         text_color="#3ddc84").pack(anchor="w", padx=8, pady=(5, 0))
            for cmd in f.fix.replace("\\\\n", chr(10)).split(chr(10)):
                if cmd.strip():
                    ctk.CTkLabel(fix_blk, text=f"  $ {cmd.strip()}",
                                 font=ctk.CTkFont(family=MONO, size=10),
                                 text_color="#5ef0a0", anchor="w",
                                 justify="left").pack(anchor="w", padx=8, pady=0)
            ctk.CTkLabel(fix_blk, text="",
                         font=ctk.CTkFont(size=2)).pack(pady=1)

            # ── MITRE ATT&CK footer ──
            foot = ctk.CTkFrame(content_col, fg_color="transparent")
            foot.pack(fill="x", padx=12, pady=(2, 10))
            ctk.CTkLabel(foot, text=f"\\u2316 MITRE ATT&CK",
                         font=ctk.CTkFont(family=MONO, size=8, weight="bold"),
                         text_color=P["purple"]).pack(side="left")
            ctk.CTkLabel(foot, text=f.mitre,
                         font=ctk.CTkFont(family=MONO, size=9),
                         text_color=P["purple"]).pack(side="left", padx=6)
            if f.evidence:
                ctk.CTkLabel(foot, text=f"\\u2502 evidence: {f.evidence[:50]}",
                             font=ctk.CTkFont(family=MONO, size=8),
                             text_color=P["dim"]).pack(side="left", padx=6)

'''
content = content[:start] + new_render + content[end:]

with open(PATH, "w") as f:
    f.write(content)
print("Шаг 4 готово: _render_rkd_findings обновлён")

# ════════════════════════════════════════════════════════════════
# 5. Обновляем _rkdefense_baseline под новую палитру/виджеты
# ════════════════════════════════════════════════════════════════
with open(PATH, "r") as f:
    content = f.read()

start = content.index("    def _rkdefense_baseline(self):")
end = content.index("    def _run_rkdefense_scan(self):")
old_bl = content[start:end]

new_bl = '''    def _rkdefense_baseline(self):
        """Создаёт baseline чистой системы."""
        P = getattr(self, "_rkd_palette", {"cyan": "#00d4ff", "amber": "#ffa726",
                                            "red": "#ff3b4e", "mono": "#7d8da5"})
        try:
            from rootkit_detector import RootkitDetector
            self.after(0, lambda: self.rkd_status.configure(
                text="создаю baseline...", text_color=P["amber"]))
            det = RootkitDetector()
            bl = det.create_baseline()
            n_bins = len(bl.get("binaries", {}))
            n_mods = len(bl.get("modules", []))
            self.app_log(f"BASELINE создан: {n_bins} бинарников, {n_mods} модулей")
            self.after(0, lambda: [
                self.rkd_status.configure(text="baseline создан", text_color=P["cyan"]),
                self.rkd_baseline_lbl.configure(
                    text=f"\\u2713 baseline: {n_bins} bins / {n_mods} mods",
                    text_color=P["cyan"]),
            ])
        except Exception as e:
            self.after(0, lambda err=str(e): self.rkd_status.configure(
                text=f"ошибка: {err[:40]}", text_color=P["red"]))

'''
content = content[:start] + new_bl + content[end:]

with open(PATH, "w") as f:
    f.write(content)
print("Шаг 5 готово: _rkdefense_baseline обновлён")

# Проверка синтаксиса
import py_compile
try:
    py_compile.compile(PATH, doraise=True)
    print("СИНТАКСИС OK")
except py_compile.PyCompileError as e:
    print(f"ОШИБКА СИНТАКСИСА: {e}")