import subprocess
import pandas as pd
import numpy as np
import joblib
from pathlib import Path

def get_interfaces():
    result = subprocess.run(["ip", "-o", "link", "show"], capture_output=True, text=True)
    ifaces = []
    for line in result.stdout.split('\n'):
        if ': ' in line:
            parts = line.split(': ')
            if len(parts) >= 2:
                iface = parts[1].strip()
                if iface != 'lo' and '@' not in iface:
                    ifaces.append(iface)
    return ifaces

def pcap_to_csv(pcap_path: str, output_csv: str = "data/live_traffic.csv") -> str:
    try:
        rf = joblib.load("models/rf_cicids.pkl")
        model_cols = list(rf.feature_names_in_)
    except Exception as e:
        print(f"[!] Модель не загружена: {e}")
        return None

    cmd = [
        "tshark", "-r", pcap_path,
        "-T", "fields",
        "-E", "separator=,",
        "-e", "tcp.dstport",
        "-e", "udp.dstport",
        "-e", "frame.len",
        "-e", "ip.ttl",
        "-e", "tcp.flags",
        "-e", "tcp.window_size",
        "-e", "tcp.len",
        "-e", "ip.proto",
        "-e", "frame.time_delta",
    ]
    print("[*] Извлекаю поля из pcap...")
    result = subprocess.run(cmd, capture_output=True, text=True)
    lines = [l for l in result.stdout.strip().split('\n') if l.strip()]
    print(f"[+] Пакетов: {len(lines)}")

    if not lines:
        print("[!] Нет данных")
        return None

    rows = []
    for line in lines:
        parts = line.split(',')
        if len(parts) < 3:
            continue
        try:
            dst_port  = float(parts[0] or parts[1] or 0)
            frame_len = float(parts[2] or 0)
            ttl       = float(parts[3] or 64)
            tcp_flags = int(parts[4] or '0', 16) if parts[4] else 0
            win_size  = float(parts[5] or 65535)
            tcp_len   = float(parts[6] or 0)
            proto     = float(parts[7] or 6)
            time_d    = float(parts[8] or 0)

            row = {col: 0.0 for col in model_cols}
            row['Dst Port']           = dst_port
            row['Protocol']           = proto
            row['Flow Duration']      = time_d * 1000000
            row['Fwd Pkt Len Max']    = frame_len
            row['Fwd Pkt Len Mean']   = frame_len * 0.8
            row['Fwd Pkt Len Min']    = frame_len * 0.3
            row['Fwd Pkt Len Std']    = frame_len * 0.1
            row['Pkt Len Max']        = frame_len
            row['Pkt Len Mean']       = frame_len * 0.7
            row['Pkt Len Min']        = frame_len * 0.2
            row['Pkt Len Std']        = frame_len * 0.1
            row['Pkt Len Var']        = (frame_len * 0.1) ** 2
            row['Pkt Size Avg']       = frame_len * 0.75
            row['Init Fwd Win Byts']  = win_size
            row['Init Bwd Win Byts']  = win_size
            row['Fwd Header Len']     = 20.0
            row['Bwd Header Len']     = 20.0
            row['Flow Pkts/s']        = 1.0 / max(time_d, 0.001)
            row['Fwd Pkts/s']         = 1.0 / max(time_d, 0.001)
            row['SYN Flag Cnt']       = 1.0 if tcp_flags & 0x02 else 0.0
            row['ACK Flag Cnt']       = 1.0 if tcp_flags & 0x10 else 0.0
            row['FIN Flag Cnt']       = 1.0 if tcp_flags & 0x01 else 0.0
            row['RST Flag Cnt']       = 1.0 if tcp_flags & 0x04 else 0.0
            row['PSH Flag Cnt']       = 1.0 if tcp_flags & 0x08 else 0.0
            rows.append(row)
        except Exception:
            continue

    if not rows:
        print("[!] Не удалось распарсить пакеты")
        return None

    df = pd.DataFrame(rows, columns=model_cols)
    df = df.replace([float('inf'), float('-inf')], 0).fillna(0)
    df.to_csv(output_csv, index=False)
    print(f"[+] CSV сохранён: {output_csv} ({len(df)} записей)")
    return output_csv

if __name__ == "__main__":
    result = pcap_to_csv("data/attack.pcap", "data/live_traffic.csv")
    if result:
        print(f"[✓] Готово: {result}")
    else:
        print("[!] Ошибка конвертации")
