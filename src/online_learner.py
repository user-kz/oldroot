"""
online_learner.py — Автономное самообучение модели
"""
import joblib
import pandas as pd
import numpy as np
import json
from pathlib import Path
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler


class OnlineLearner:
    def __init__(self):
        self.rf_path     = "models/rf_rootkitguard.pkl"   # RKG-модель для самообучения
        self.rf_seed_path = "models/rf_default.pkl"        # стартовая если RKG ещё нет
        self.scaler_path = "models/scaler_cicids.pkl"
        self.log_path    = "data/evolution_log.json"
        self.buffer_path = "data/learning_buffer.csv"
        self.rf          = None
        self.scaler      = None
        self.buffer      = []
        self.min_samples = 50   # минимум для дообучения
        self.version     = 1
        self._load()

    def _load(self):
        try:
            from pathlib import Path as _P
            _src = self.rf_path if _P(self.rf_path).exists() else self.rf_seed_path
            self.rf     = joblib.load(_src)
            self.scaler = joblib.load(self.scaler_path)
        except Exception as e:
            print(f"[OnlineLearner] Ошибка загрузки: {e}")

        # Загружаем буфер если есть
        if Path(self.buffer_path).exists():
            try:
                df = pd.read_csv(self.buffer_path)
                self.buffer = df.to_dict('records')
            except Exception:
                pass

        # Загружаем версию
        if Path(self.log_path).exists():
            try:
                log = json.loads(Path(self.log_path).read_text())
                self.version = log.get("version", 1)
            except Exception:
                pass

    def add_sample(self, features: dict, label: int):
        """Добавляем новый образец в буфер"""
        features['_label'] = label
        features['_ts']    = datetime.now().isoformat()
        self.buffer.append(features)

        # Сохраняем буфер
        try:
            Path("data").mkdir(exist_ok=True)
            df = pd.DataFrame(self.buffer)
            df.to_csv(self.buffer_path, index=False)
        except Exception:
            pass

        return len(self.buffer)

    def add_attack_samples(self, df: pd.DataFrame, label: int = 1):
        """Добавляем DataFrame как атаку (label=1) или норму (label=0)"""
        count = 0
        for _, row in df.iterrows():
            self.add_sample(row.to_dict(), label)
            count += 1
        return count

    def should_retrain(self) -> bool:
        return len(self.buffer) >= self.min_samples

    def retrain(self) -> dict:
        """Дообучаем модель на новых данных"""
        if not self.should_retrain():
            return {"status": "not_enough_data",
                    "samples": len(self.buffer),
                    "needed":  self.min_samples}

        try:
            df     = pd.DataFrame(self.buffer)
            labels = df['_label'].values
            df     = df.drop(columns=['_label', '_ts'], errors='ignore')

            # Получаем колонки модели
            cols = list(self.rf.feature_names_in_)
            for c in cols:
                if c not in df.columns:
                    df[c] = 0
            df = df[cols]
            df = df.replace([float('inf'), float('-inf')], 0).fillna(0)

            # Масштабируем
            X = self.scaler.transform(df)

            # Дообучаем — добавляем новые деревья
            new_estimators = []
            new_rf = RandomForestClassifier(
                n_estimators=20,
                max_depth=8,
                class_weight='balanced',
                random_state=int(datetime.now().timestamp()),
                n_jobs=-1)
            new_rf.fit(X, labels)
            new_estimators = new_rf.estimators_

            # Добавляем новые деревья к старым
            old_estimators  = self.rf.estimators_
            all_estimators  = old_estimators + new_estimators
            self.rf.estimators_ = all_estimators
            self.rf.n_estimators = len(all_estimators)

            # Сохраняем
            self.version += 1
            joblib.dump(self.rf, self.rf_path)

            # Логируем эволюцию
            log_entry = {
                "version":    self.version,
                "timestamp":  datetime.now().isoformat(),
                "new_samples": len(self.buffer),
                "new_trees":   len(new_estimators),
                "total_trees": len(all_estimators),
                "labels": {
                    "anomaly": int((labels == 1).sum()),
                    "normal":  int((labels == 0).sum()),
                },
                "status": "success"
            }
            self._save_log(log_entry)

            # Очищаем буфер
            self.buffer = []
            Path(self.buffer_path).unlink(missing_ok=True)

            return log_entry

        except Exception as e:
            return {"status": "error", "msg": str(e)}

    def _save_log(self, entry: dict):
        Path("data").mkdir(exist_ok=True)
        history = []
        if Path(self.log_path).exists():
            try:
                data    = json.loads(Path(self.log_path).read_text())
                history = data.get("history", [])
            except Exception:
                pass
        history.append(entry)
        Path(self.log_path).write_text(json.dumps({
            "version": self.version,
            "history": history[-20:],  # последние 20 записей
        }, ensure_ascii=False, indent=2))

    def get_evolution_log(self) -> list:
        if Path(self.log_path).exists():
            try:
                return json.loads(Path(self.log_path).read_text()).get("history", [])
            except Exception:
                pass
        return []

    def get_status(self) -> dict:
        return {
            "version":       self.version,
            "buffer_size":   len(self.buffer),
            "min_samples":   self.min_samples,
            "ready":         self.should_retrain(),
            "total_trees":   len(self.rf.estimators_) if self.rf else 0,
        }
