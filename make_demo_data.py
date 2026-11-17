"""Generate a SYNTHETIC CSV with the same main columns as TON_IoT train_test_network.csv.

Only for testing the pipeline when the real Kaggle file is not available.
Do NOT report results obtained on this file as results on TON_IoT.
"""
import argparse
import numpy as np
import pandas as pd

p = argparse.ArgumentParser()
p.add_argument("--rows", type=int, default=100_000)
p.add_argument("--out", default="demo_ton_iot_network.csv")
p.add_argument("--seed", type=int, default=42)
a = p.parse_args()
rng = np.random.default_rng(a.seed)
n = a.rows

internal = [f"192.168.1.{i}" for i in range(30, 60)]
external = [f"{rng.integers(1,223)}.{rng.integers(0,255)}.{rng.integers(0,255)}.{rng.integers(1,254)}" for _ in range(300)]
types = ["normal", "backdoor", "ddos", "dos", "injection", "mitm", "password", "ransomware", "scanning", "xss"]
tprob = [0.40, 0.05, 0.12, 0.08, 0.06, 0.02, 0.10, 0.03, 0.10, 0.04]
typ = rng.choice(types, n, p=tprob)
src = np.where(rng.random(n) < 0.7, rng.choice(internal, n), rng.choice(external, n))
dst = np.where(rng.random(n) < 0.5, rng.choice(internal, n), rng.choice(external, n))
ports = np.array([80, 443, 53, 21, 22, 1883, 8080, 445, 3389, 5353])
dport = np.where(rng.random(n) < 0.8, rng.choice(ports, n), rng.integers(1024, 65535, n))
service = np.select([dport == 80, dport == 443, dport == 53, dport == 21],
                    ["http", "ssl", "dns", "ftp"], default="-")
ts = 1554118516 + np.sort(rng.integers(0, 3 * 86400, n))
df = pd.DataFrame({
    "ts": ts, "src_ip": src, "src_port": rng.integers(1024, 65535, n),
    "dst_ip": dst, "dst_port": dport, "proto": rng.choice(["tcp", "udp", "icmp"], n, p=[.7, .27, .03]),
    "service": service, "duration": rng.exponential(2.0, n).round(4),
    "src_bytes": rng.lognormal(5, 2, n).astype(int), "dst_bytes": rng.lognormal(5, 2, n).astype(int),
    "conn_state": rng.choice(["SF", "S0", "REJ", "RSTO"], n),
    "label": (typ != "normal").astype(int), "type": typ,
})
df.to_csv(a.out, index=False)
print(f"wrote {a.out} ({n} rows)")
