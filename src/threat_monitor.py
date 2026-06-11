"""
threat_monitor.py — Adaptive Threat Detection System v2
"""
import threading
import subprocess
import time
import joblib
import pandas as pd
import numpy as np
from pathlib import Path
from datetime import datetime
from collections import deque, defaultdict


class ThreatMonitor:
    def __init__(self, interface="enp0s3", interval=5, attacker_ip=None):
        self.interface    = interface
        self.interval     = interval
        self.attacker_ip  = attacker_ip  # IP Kali — фильтруем только его трафик
        self.running      = False
        self._thread      = None
        self.callbacks    = []
        self.history      = deque(maxlen=60)
        self.threat_score = 0
        self.cycle        = 0
        self.attack_start = None
        self.consecutive_normal = 0  # счётчик нормальных циклов подряд
        self.rf     = None
        self.scaler = None
        self._load_models()

    def _load_models(self):
        try:
            self.rf     = joblib.load("models/rf_cicids.pkl")
            self.scaler = joblib.load("models/scaler_cicids.pkl")
        except Exception as e:
            print(f"[ThreatMonitor] Модель не загружена: {e}")

    def add_callback(self, fn):
        self.callbacks.append(fn)

    def _notify(self, event: dict):
        for cb in self.callbacks:
            try:
                cb(event)
            except Exception:
                pass

    def start(self):
        if self.running:
            return
        self.running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self.running = False

    def _capture(self, pcap_path: str) -> bool:
        Path("data").mkdir(exist_ok=True)

        # Фильтр — только TCP трафик направленный на нас
        # Если знаем IP атакующего — фильтруем только его
        if self.attacker_ip:
            bpf = f"tcp and host {self.attacker_ip}"
        else:
            bpf = "tcp"  # только TCP — убираем ARP, STP, broadcast

        cmd = ["tshark", "-i", self.interface,
               "-w", pcap_path,
               "-a", f"duration:{self.interval}",
               "-f", bpf,
               "-q"]
        proc = subprocess.Popen(cmd,
                                 stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
        proc.wait()
        exists = Path(pcap_path).exists()
        size   = Path(pcap_path).stat().st_size if exists else 0
        return exists and size > 100

    def _pcap_to_flows(self, pcap_path: str) -> pd.DataFrame:
        if not self.rf:
            return None
        model_cols = list(self.rf.feature_names_in_)

        cmd = [
            "tshark", "-r", pcap_path,
            "-T", "fields", "-E", "separator=|",
            "-e", "ip.src", "-e", "ip.dst",
            "-e", "tcp.srcport", "-e", "tcp.dstport",
            "-e", "ip.proto",
            "-e", "frame.len",
            "-e", "frame.time_epoch",
            "-e", "tcp.flags",
            "-e", "tcp.window_size",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        lines  = [l for l in result.stdout.strip().split('\n') if l.strip()]

        if not lines:
            return None

        flows = defaultdict(list)
        for line in lines:
            p = line.split('|')
            if len(p) < 8:
                continue
            try:
                src_ip   = p[0].strip()
                dst_ip   = p[1].strip()
                src_port = p[2].strip() or '0'
                dst_port = p[3].strip() or '0'
                proto    = p[4].strip() or '6'
                pkt_len  = float(p[5] or 0)
                ts       = float(p[6] or 0)
                flags    = int(p[7] or '0', 16) if p[7].strip() else 0
                win_size = float(p[8] or 65535) if len(p) > 8 else 65535

                # Пропускаем пустые или локальные
                if not src_ip or not dst_ip:
                    continue
                if src_ip == dst_ip:
                    continue

                flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}"
                flows[flow_key].append({
                    'len':      pkt_len,
                    'ts':       ts,
                    'flags':    flags,
                    'win':      win_size,
                    'dst_port': int(dst_port or 0),
                    'proto':    int(proto or 6),
                })
            except Exception:
                continue

        if not flows:
            return None

        rows = []
        for flow_key, pkts in flows.items():
            if len(pkts) < 2:  # минимум 2 пакета для flow
                continue
            try:
                lens  = [p['len'] for p in pkts]
                times = sorted([p['ts'] for p in pkts])

                duration = (times[-1] - times[0]) * 1e6 if len(times) > 1 else 1
                iats     = [(times[i+1]-times[i])*1e6 for i in range(len(times)-1)]
                iat_mean = float(np.mean(iats)) if iats else 0
                iat_std  = float(np.std(iats))  if iats else 0
                iat_max  = float(max(iats))      if iats else 0
                iat_min  = float(min(iats))      if iats else 0

                n_fwd    = max(len(pkts) // 2, 1)
                fwd_pkts = pkts[:n_fwd]
                bwd_pkts = pkts[n_fwd:]
                fwd_lens = [p['len'] for p in fwd_pkts]
                bwd_lens = [p['len'] for p in bwd_pkts] or [0]

                syn_cnt = sum(1 for p in pkts if p['flags'] & 0x02)
                ack_cnt = sum(1 for p in pkts if p['flags'] & 0x10)
                fin_cnt = sum(1 for p in pkts if p['flags'] & 0x01)
                rst_cnt = sum(1 for p in pkts if p['flags'] & 0x04)
                psh_cnt = sum(1 for p in pkts if p['flags'] & 0x08)
                urg_cnt = sum(1 for p in pkts if p['flags'] & 0x20)

                dur_sec = max(duration / 1e6, 0.001)

                row = {col: 0.0 for col in model_cols}
                row['Dst Port']          = float(pkts[0]['dst_port'])
                row['Protocol']          = float(pkts[0]['proto'])
                row['Flow Duration']     = duration
                row['Tot Fwd Pkts']      = float(len(fwd_pkts))
                row['Tot Bwd Pkts']      = float(len(bwd_pkts))
                row['TotLen Fwd Pkts']   = float(sum(fwd_lens))
                row['TotLen Bwd Pkts']   = float(sum(bwd_lens))
                row['Fwd Pkt Len Max']   = float(max(fwd_lens))
                row['Fwd Pkt Len Min']   = float(min(fwd_lens))
                row['Fwd Pkt Len Mean']  = float(np.mean(fwd_lens))
                row['Fwd Pkt Len Std']   = float(np.std(fwd_lens))
                row['Bwd Pkt Len Max']   = float(max(bwd_lens))
                row['Bwd Pkt Len Min']   = float(min(bwd_lens))
                row['Bwd Pkt Len Mean']  = float(np.mean(bwd_lens))
                row['Bwd Pkt Len Std']   = float(np.std(bwd_lens))
                row['Flow Byts/s']       = sum(lens) / dur_sec
                row['Flow Pkts/s']       = len(pkts)  / dur_sec
                row['Flow IAT Mean']     = iat_mean
                row['Flow IAT Std']      = iat_std
                row['Flow IAT Max']      = iat_max
                row['Flow IAT Min']      = iat_min
                row['Fwd IAT Tot']       = duration
                row['Fwd IAT Mean']      = iat_mean
                row['Fwd IAT Std']       = iat_std
                row['Fwd IAT Max']       = iat_max
                row['Fwd IAT Min']       = iat_min
                row['Pkt Len Min']       = float(min(lens))
                row['Pkt Len Max']       = float(max(lens))
                row['Pkt Len Mean']      = float(np.mean(lens))
                row['Pkt Len Std']       = float(np.std(lens))
                row['Pkt Len Var']       = float(np.var(lens))
                row['FIN Flag Cnt']      = float(fin_cnt)
                row['SYN Flag Cnt']      = float(syn_cnt)
                row['RST Flag Cnt']      = float(rst_cnt)
                row['PSH Flag Cnt']      = float(psh_cnt)
                row['ACK Flag Cnt']      = float(ack_cnt)
                row['URG Flag Cnt']      = float(urg_cnt)
                row['Pkt Size Avg']      = float(np.mean(lens))
                row['Fwd Seg Size Avg']  = float(np.mean(fwd_lens))
                row['Bwd Seg Size Avg']  = float(np.mean(bwd_lens))
                row['Init Fwd Win Byts'] = float(pkts[0]['win'])
                row['Init Bwd Win Byts'] = float(pkts[-1]['win'])
                row['Fwd Pkts/s']        = len(fwd_pkts) / dur_sec
                row['Bwd Pkts/s']        = len(bwd_pkts) / dur_sec
                row['Down/Up Ratio']     = len(bwd_pkts) / max(len(fwd_pkts), 1)
                row['Fwd Header Len']    = 20.0 * len(fwd_pkts)
                row['Bwd Header Len']    = 20.0 * len(bwd_pkts)
                row['Fwd Seg Size Min']  = float(min(fwd_lens))
                rows.append(row)
            except Exception:
                continue

        if not rows:
            return None

        df = pd.DataFrame(rows, columns=model_cols)
        return df.replace([float('inf'), float('-inf')], 0).fillna(0)

    def _analyze(self, df: pd.DataFrame) -> dict:
        X     = pd.DataFrame(self.scaler.transform(df), columns=df.columns)
        cols  = self.rf.feature_names_in_
        for c in cols:
            if c not in X.columns:
                X[c] = 0
        X     = X[cols]
        preds = self.rf.predict(X)
        proba = self.rf.predict_proba(X)[:, 1]

        n_anom = int(preds.sum())
        n_norm = len(preds) - n_anom
        pct    = n_anom / max(len(preds), 1) * 100

        # Более строгие пороги чтобы избежать false positive
        threat = "ВЫСОКАЯ" if (pct > 40 and len(preds) > 10) else "СРЕДНЯЯ" if (pct > 15 and len(preds) > 5) else "НИЗКАЯ"

        top_ports = []
        if "Dst Port" in df.columns:
            top_ports = df[preds==1]["Dst Port"].value_counts().head(3).index.tolist()

        attack_type = "Нормальный трафик"
        if pct > 15 and top_ports:
            port_map = {
                80:   "HTTP Flood",
                443:  "HTTPS Flood",
                445:  "SMB Attack (EternalBlue)",
                3389: "RDP Brute Force",
                22:   "SSH Brute Force",
                53:   "DNS Flood",
                1433: "SQL Injection",
                4444: "Backdoor/Metasploit",
                6666: "Bot C&C",
                8080: "HTTP Proxy Attack",
            }
            for p in top_ports:
                if int(p) in port_map:
                    attack_type = port_map[int(p)]
                    break
            if attack_type == "Нормальный трафик":
                attack_type = "Port Scan / SYN Flood"

        return {
            "total":       len(preds),
            "anomalies":   n_anom,
            "normal":      n_norm,
            "pct":         round(pct, 2),
            "threat":      threat,
            "top_ports":   [int(p) for p in top_ports],
            "max_proba":   round(float(proba.max()), 4),
            "attack_type": attack_type,
            "timestamp":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

    def _update_score(self, threat: str):
        if threat == "ВЫСОКАЯ":
            self.consecutive_normal = 0
            self.threat_score = min(100, self.threat_score + 30)
        elif threat == "СРЕДНЯЯ":
            self.consecutive_normal = 0
            self.threat_score = min(100, self.threat_score + 10)
        else:
            self.consecutive_normal += 1
            # Быстро снижаем score если несколько циклов подряд норма
            drop = min(20 * self.consecutive_normal, 40)
            self.threat_score = max(0, self.threat_score - drop)

    def _loop(self):
        while self.running:
            self.cycle += 1
            ts        = datetime.now().strftime("%H:%M:%S")
            pcap_path = f"data/live_{self.cycle}.pcap"
            self._notify({"type": "cycle_start", "cycle": self.cycle, "ts": ts})
            try:
                ok = self._capture(pcap_path)
                if not ok:
                    self._notify({"type": "no_traffic", "cycle": self.cycle, "ts": ts})
                    # Снижаем score при отсутствии трафика
                    self.consecutive_normal += 1
                    drop = min(20 * self.consecutive_normal, 40)
                    self.threat_score = max(0, self.threat_score - drop)
                    continue

                df = self._pcap_to_flows(pcap_path)
                if df is None or len(df) == 0:
                    self._notify({"type": "no_data", "cycle": self.cycle, "ts": ts})
                    self.threat_score = max(0, self.threat_score - 10)
                    continue

                result          = self._analyze(df)
                result["cycle"] = self.cycle
                self._update_score(result["threat"])
                result["threat_score"] = self.threat_score

                if result["threat"] == "ВЫСОКАЯ" and not self.attack_start:
                    self.attack_start = ts
                    result["attack_event"] = "start"
                elif result["threat"] == "НИЗКАЯ" and self.attack_start:
                    result["attack_event"] = "end"
                    result["attack_duration"] = f"{self.attack_start} → {ts}"
                    self.attack_start = None

                self.history.append(result)
                self._notify({"type": "result", "data": result})

            except Exception as e:
                self._notify({"type": "error", "msg": str(e), "cycle": self.cycle})
            finally:
                try:
                    Path(pcap_path).unlink()
                except Exception:
                    pass

    def get_history(self):
        return list(self.history)

    def set_attacker_ip(self, ip: str):
        self.attacker_ip = ip

    def set_model(self, model_name: str):
        import joblib
        from pathlib import Path
        try:
            rf_default = joblib.load("models/rf_default.pkl")
        except:
            rf_default = self.rf

        try:
            xgb_model = joblib.load("models/xgb_cicids.pkl")
        except:
            xgb_model = rf_default

        try:
            iso_model = joblib.load("models/iso_cicids.pkl")
        except:
            iso_model = rf_default

        try:
            rkg_path = "models/rf_rootkitguard.pkl"
            rkg_model = joblib.load(rkg_path) if Path(rkg_path).exists() else rf_default
        except:
            rkg_model = rf_default

        models = {
            "rf":           rf_default,
            "xgb":          xgb_model,
            "iso":          iso_model,
            "rootkitguard": rkg_model,
        }
        self.rf = models.get(model_name, rf_default)
        self.current_model_name = {
            "rf":           "Random Forest",
            "xgb":          "XGBoost",
            "iso":          "Isolation Forest",
            "rootkitguard": "RootkitGuard ML",
        }.get(model_name, "Random Forest")
