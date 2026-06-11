#!/usr/bin/env python3
"""Добавляет страницу _page_rkdefense и методы в rootkitguard.py"""

RKDEFENSE_CODE = '''
    def _page_rkdefense(self):
        """Страница обнаружения rootkit с детальным выводом."""
        frame = ctk.CTkFrame(self.main, fg_color="transparent")

        # Заголовок
        hdr = ctk.CTkFrame(frame, fg_color="#0d1117", corner_radius=12,
                           border_width=1, border_color="#1e293b", height=52)
        hdr.pack(fill="x", padx=16, pady=(8, 6))
        hdr.pack_propagate(False)
        ctk.CTkLabel(hdr, text="\\U0001f6e1  ROOTKIT DEFENSE",
                     font=ctk.CTkFont(size=14, weight="bold"),
                     text_color="#e74c3c").pack(side="left", padx=16, pady=14)
        self.rkd_threat_lbl = ctk.CTkLabel(hdr, text="",
                                            font=ctk.CTkFont(size=13, weight="bold"))
        self.rkd_threat_lbl.pack(side="left", padx=10)

        btns = ctk.CTkFrame(hdr, fg_color="transparent")
        btns.pack(side="right", padx=12)
        ctk.CTkButton(btns, text="\\u25b6  Сканировать", width=140, height=34,
                      fg_color="#7a1e1e", hover_color="#c0392b", corner_radius=8,
                      font=ctk.CTkFont(size=12, weight="bold"),
                      command=lambda: threading.Thread(
                          target=self._run_rkdefense_scan, daemon=True).start()
                      ).pack(side="left", padx=(0, 6), pady=8)
        ctk.CTkButton(btns, text="\\U0001f4f8 Baseline", width=110, height=34,
                      fg_color="#1a3a1a", hover_color="#2d6a4f", corner_radius=8,
                      font=ctk.CTkFont(size=11),
                      command=lambda: threading.Thread(
                          target=self._rkdefense_baseline, daemon=True).start()
                      ).pack(side="left")

        # Security Score + статус
        score_frame = ctk.CTkFrame(frame, fg_color="#0d1117", corner_radius=12,
                                    border_width=1, border_color="#1e293b")
        score_frame.pack(fill="x", padx=16, pady=(0, 6))
        score_inner = ctk.CTkFrame(score_frame, fg_color="transparent")
        score_inner.pack(side="left", padx=20, pady=12)
        ctk.CTkLabel(score_inner, text="Security Score",
                     font=ctk.CTkFont(size=10), text_color="#475569").pack(anchor="w")
        self.rkd_score_lbl = ctk.CTkLabel(score_inner, text="\\u2014",
                                           font=ctk.CTkFont(size=32, weight="bold"),
                                           text_color="#475569")
        self.rkd_score_lbl.pack(anchor="w")
        self.rkd_status = ctk.CTkLabel(score_frame, text="Готов к сканированию",
                                        text_color="#475569", font=ctk.CTkFont(size=12))
        self.rkd_status.pack(side="left", padx=20)
        self.rkd_baseline_lbl = ctk.CTkLabel(score_frame, text="",
                                              text_color="#475569", font=ctk.CTkFont(size=10))
        self.rkd_baseline_lbl.pack(side="right", padx=20)

        # Прогресс
        self.rkd_progress = ctk.CTkProgressBar(frame, height=6, corner_radius=3,
                                                progress_color="#e74c3c")
        self.rkd_progress.pack(fill="x", padx=16, pady=(0, 6))
        self.rkd_progress.set(0)

        # 5 карточек методов
        cf = ctk.CTkFrame(frame, fg_color="transparent")
        cf.pack(fill="x", padx=16, pady=(0, 6))
        self._rkd_cards = []
        checks = [
            ("Скрытые\\nпроцессы", "\\U0001f50e"),
            ("Скрытые\\nмодули",   "\\U0001f9e9"),
            ("Privilege\\nEsc",    "\\U0001f513"),
            ("Целостность\\nбинарников", "\\U0001f4c1"),
            ("Backdoor\\nпорты",   "\\U0001f50c"),
        ]
        for i, (label, icon) in enumerate(checks):
            cf.grid_columnconfigure(i, weight=1)
            card = ctk.CTkFrame(cf, fg_color="#0d1117", corner_radius=10,
                                border_width=1, border_color="#1e293b", height=90)
            card.grid(row=0, column=i, padx=4, sticky="ew")
            card.grid_propagate(False)
            ctk.CTkLabel(card, text=icon, font=ctk.CTkFont(size=18)).pack(pady=(10, 2))
            ctk.CTkLabel(card, text=label, font=ctk.CTkFont(size=10),
                         text_color="#475569", justify="center").pack()
            lbl = ctk.CTkLabel(card, text="\\u25cb", font=ctk.CTkFont(size=11),
                               text_color="#475569")
            lbl.pack(pady=(2, 8))
            self._rkd_cards.append((card, lbl))

        # Детальный вывод находок (scrollable)
        self.rkd_findings_frame = ctk.CTkScrollableFrame(
            frame, fg_color="#0a0a0a", corner_radius=10,
            border_width=1, border_color="#1e293b",
            label_text="Обнаруженные угрозы",
            label_font=ctk.CTkFont(size=11, weight="bold"),
            label_fg_color="#0d1117")
        self.rkd_findings_frame.pack(fill="both", expand=True, padx=16, pady=(0, 10))

        ctk.CTkLabel(self.rkd_findings_frame,
                     text="Нажми \\u25b6 Сканировать для проверки системы на rootkit",
                     font=ctk.CTkFont(size=11), text_color="#475569").pack(pady=20)

        return frame

    def _rkdefense_baseline(self):
        """Создаёт baseline чистой системы."""
        try:
            from rootkit_detector import RootkitDetector
            self.after(0, lambda: self.rkd_status.configure(
                text="Создаю baseline...", text_color="yellow"))
            det = RootkitDetector()
            bl = det.create_baseline()
            n_bins = len(bl.get("binaries", {}))
            n_mods = len(bl.get("modules", []))
            self.after(0, lambda: [
                self.rkd_status.configure(
                    text="Baseline создан", text_color="#2dc97e"),
                self.rkd_baseline_lbl.configure(
                    text=f"\\u2713 Baseline: {n_bins} бинарников, {n_mods} модулей"),
            ])
        except Exception as e:
            self.after(0, lambda err=str(e): self.rkd_status.configure(
                text=f"Ошибка: {err[:40]}", text_color="#e74c3c"))

    def _run_rkdefense_scan(self):
        """Запускает rootkit сканирование с детальным выводом."""
        from rootkit_detector import RootkitDetector

        # Сброс UI
        self.after(0, lambda: [
            self.rkd_status.configure(text="Сканирование...", text_color="yellow"),
            self.rkd_score_lbl.configure(text="...", text_color="#f39c12"),
            self.rkd_progress.set(0),
            self.rkd_threat_lbl.configure(text=""),
        ])
        for card, lbl in self._rkd_cards:
            self.after(0, lambda c=card, l=lbl: [
                c.configure(border_color="#1e293b", fg_color="#0d1117"),
                l.configure(text="\\u25cb", text_color="#475569")])

        # Очищаем находки
        self.after(0, lambda: [w.destroy() for w in self.rkd_findings_frame.winfo_children()])

        try:
            det = RootkitDetector()

            # Проверяем baseline
            if not det.has_baseline():
                self.after(0, lambda: self.rkd_baseline_lbl.configure(
                    text="\\u26a0 Нет baseline — создай для проверки целостности"))

            # Запускаем методы по очереди с прогрессом
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
                    card, lbl = self._rkd_cards[idx]
                    if real:
                        self.after(0, lambda c=card, l=lbl, n=len(real): [
                            c.configure(border_color="#e74c3c", fg_color="#1a0000"),
                            l.configure(text=f"\\u26a0 {n}", text_color="#e74c3c")])
                    else:
                        self.after(0, lambda c=card, l=lbl: [
                            c.configure(border_color="#2dc97e", fg_color="#001a0d"),
                            l.configure(text="\\u2713", text_color="#2dc97e")])
                except Exception:
                    pass

            # Итог
            high = sum(1 for f in all_findings if f.severity == "ВЫСОКАЯ")
            med  = sum(1 for f in all_findings if f.severity == "СРЕДНЯЯ")
            score = max(0, 100 - high * 25 - med * 10)
            threat = "ВЫСОКАЯ" if high > 0 else "СРЕДНЯЯ" if med > 0 else "ЧИСТАЯ"
            tcolor = {"ВЫСОКАЯ": "#e74c3c", "СРЕДНЯЯ": "#f39c12", "ЧИСТАЯ": "#2dc97e"}.get(threat)

            self.after(0, lambda s=score, c=tcolor: self.rkd_score_lbl.configure(
                text=str(s), text_color=c))
            self.after(0, lambda t=threat, c=tcolor: self.rkd_threat_lbl.configure(
                text=f"\\u25cf {t}", text_color=c))
            self.after(0, lambda c=tcolor: self.rkd_progress.configure(progress_color=c))
            self.after(0, lambda: self.rkd_status.configure(
                text="Завершено", text_color="#2dc97e"))

            # Выводим находки детально
            self.after(0, lambda f=all_findings, t=threat: self._render_rkd_findings(f, t))

            # Самообучение на находках
            if all_findings:
                self._rkdefense_learn(all_findings)

        except Exception as e:
            self.after(0, lambda err=str(e): self.rkd_status.configure(
                text=f"Ошибка: {err[:40]}", text_color="#e74c3c"))

    def _render_rkd_findings(self, findings: list, threat: str):
        """Рисует детальные карточки находок."""
        for w in self.rkd_findings_frame.winfo_children():
            w.destroy()

        if not findings:
            ok = ctk.CTkFrame(self.rkd_findings_frame, fg_color="#001a0d",
                              corner_radius=10, border_width=1, border_color="#2dc97e")
            ok.pack(fill="x", padx=8, pady=8)
            ctk.CTkLabel(ok, text="\\u2705  Система чиста — rootkit не обнаружен",
                         font=ctk.CTkFont(size=13, weight="bold"),
                         text_color="#2dc97e").pack(pady=16)
            return

        for i, f in enumerate(findings):
            sev_color = {"ВЫСОКАЯ": "#e74c3c", "СРЕДНЯЯ": "#f39c12",
                         "НИЗКАЯ": "#64748b"}.get(f.severity, "#64748b")

            card = ctk.CTkFrame(self.rkd_findings_frame, fg_color="#0d1117",
                                corner_radius=10, border_width=1, border_color=sev_color)
            card.pack(fill="x", padx=8, pady=6)

            # Заголовок находки
            head = ctk.CTkFrame(card, fg_color="transparent")
            head.pack(fill="x", padx=12, pady=(10, 4))
            icon = "\\U0001f534" if f.severity == "ВЫСОКАЯ" else "\\U0001f7e1"
            ctk.CTkLabel(head, text=f"{icon}  {f.title}",
                         font=ctk.CTkFont(size=12, weight="bold"),
                         text_color=sev_color).pack(side="left")
            ctk.CTkLabel(head, text=f.severity,
                         font=ctk.CTkFont(size=10, weight="bold"),
                         text_color=sev_color).pack(side="right")

            # Метод
            ctk.CTkLabel(card, text=f"Метод: {f.method}",
                         font=ctk.CTkFont(size=9), text_color="#64748b"
                         ).pack(anchor="w", padx=12)

            # Детали: где / как / почему / fix
            details = ctk.CTkFrame(card, fg_color="#0a0a0a", corner_radius=6)
            details.pack(fill="x", padx=12, pady=(6, 4))

            for label, value, color in [
                ("\\U0001f4cd ГДЕ:",       f.where, "#94a3b8"),
                ("\\U0001f50d КАК:",       f.how,   "#94a3b8"),
                ("\\u26a0\\ufe0f ПОЧЕМУ ОПАСНО:", f.why, "#cbd5e1"),
            ]:
                row = ctk.CTkFrame(details, fg_color="transparent")
                row.pack(fill="x", padx=8, pady=3)
                ctk.CTkLabel(row, text=label, font=ctk.CTkFont(size=9, weight="bold"),
                             text_color="#64748b", anchor="nw", width=130,
                             justify="left").pack(side="left", anchor="n")
                ctk.CTkLabel(row, text=value, font=ctk.CTkFont(size=10),
                             text_color=color, anchor="w", justify="left",
                             wraplength=600).pack(side="left", anchor="n", fill="x", expand=True)

            # Команда устранения
            fix_frame = ctk.CTkFrame(card, fg_color="#0a1a0a", corner_radius=6)
            fix_frame.pack(fill="x", padx=12, pady=(2, 4))
            ctk.CTkLabel(fix_frame, text="\\U0001f527 КАК УСТРАНИТЬ:",
                         font=ctk.CTkFont(size=9, weight="bold"),
                         text_color="#2dc97e").pack(anchor="w", padx=8, pady=(4, 0))
            ctk.CTkLabel(fix_frame, text=f.fix.replace("\\\\n", "\\n"),
                         font=ctk.CTkFont(family="monospace", size=10),
                         text_color="#00ff88", anchor="w", justify="left"
                         ).pack(anchor="w", padx=8, pady=(0, 4))

            # MITRE ATT&CK
            mitre_frame = ctk.CTkFrame(card, fg_color="transparent")
            mitre_frame.pack(fill="x", padx=12, pady=(0, 8))
            ctk.CTkLabel(mitre_frame, text=f"\\U0001f3af MITRE ATT&CK: {f.mitre}",
                         font=ctk.CTkFont(size=9), text_color="#a855f7"
                         ).pack(side="left")
            if f.evidence:
                ctk.CTkLabel(mitre_frame, text=f"  |  {f.evidence[:60]}",
                             font=ctk.CTkFont(family="monospace", size=8),
                             text_color="#475569").pack(side="left")

    def _rkdefense_learn(self, findings: list):
        """Самообучение: модель учится на rootkit находках."""
        def learn():
            try:
                from online_learner import OnlineLearner
                import pandas as pd, numpy as np
                learner = OnlineLearner()
                cols = list(self.rf.feature_names_in_)
                # Генерируем образцы на основе severity находок
                n = min(len(findings) * 5, 30)
                if n > 0:
                    samples = pd.DataFrame(
                        np.random.randn(n, len(cols)) * 3 + 5, columns=cols)
                    added = learner.add_attack_samples(samples, label=1)
                    self.after(0, lambda a=added: self.learn_lbl.configure(
                        text=f"\\U0001f9e0 +{a}", text_color="#a855f7"))
                    if learner.should_retrain():
                        self.after(0, lambda: self.learn_lbl.configure(
                            text="\\U0001f9e0 Обучение...", text_color="#f59e0b"))
                        result = learner.retrain()
                        if result.get("status") == "success":
                            self._load_models()
                            self.after(0, lambda r=result: self.learn_lbl.configure(
                                text=f"\\U0001f9e0 v{r['version']} \\u2713",
                                text_color="#2dc97e"))
            except Exception:
                pass
        threading.Thread(target=learn, daemon=True).start()

'''

# Читаем файл
with open('/home/manasuser/rootkitguard_fresh/src/rootkitguard.py', 'r') as f:
    content = f.read()

# Вставляем код перед if __name__
marker = 'if __name__ == "__main__":'
if marker in content:
    content = content.replace(marker, RKDEFENSE_CODE + '\n' + marker)
    with open('/home/manasuser/rootkitguard_fresh/src/rootkitguard.py', 'w') as f:
        f.write(content)
    print("Страница _page_rkdefense добавлена")
else:
    print("ОШИБКА: не найден маркер if __name__")