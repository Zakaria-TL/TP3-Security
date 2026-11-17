#!/usr/bin/env python3
"""TP3 - Part A: anonymization of the TON_IoT network dataset.

Steps (same numbering as the TP handout):
  1. load dataset
  2. identify identifiers / quasi-identifiers / sensitive attribute + linkage attack
  3. k-anonymity (k = 2, 5, 10) with generalization + suppression
  4. differential privacy (Laplace mechanism, eps = 0.1, 1, 10)
  5. utility vs privacy measures + plots
"""
import argparse
import itertools
import json
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

# ---------------------------------------------------------------- configuration
QIS = ["src_ip", "dst_ip", "src_port", "dst_port", "service"]   # quasi-identifiers
SENSITIVE = "type"                                       # sensitive attribute (attack class)
MAXLV = {"src_ip": 4, "dst_ip": 4, "src_port": 3, "dst_port": 3, "service": 2}   # hierarchy heights
NEEDED = ["src_ip", "dst_ip", "src_port", "dst_port", "service", "src_bytes", "type"]
DP_GROUP = "service"                                     # DP query: mean src_bytes per service


# ---------------------------------------------------------------- loading
def load_data(path, sample, seed):
    with open(path, encoding="utf-8-sig") as f:               # handles BOM
        first = f.readline()
    sep = ";" if first.count(";") > first.count(",") else ","  # TON_IoT Kaggle file uses ';'
    header = pd.read_csv(path, sep=sep, encoding="utf-8-sig", nrows=0).columns.str.strip()
    missing = [c for c in NEEDED if c not in header and c != "type"]
    if missing:
        sys.exit(f"Missing columns {missing}. Columns found: {list(header)}")
    use = [c for c in NEEDED + ["label"] if c in header]
    df = pd.read_csv(path, sep=sep, encoding="utf-8-sig", usecols=use, low_memory=False)
    df = df.dropna(subset=["src_ip"]).reset_index(drop=True)  # file has empty trailing rows/cols
    if "type" not in df.columns:                              # fall back on binary label
        df["type"] = df["label"].map({0: "normal", 1: "attack"})
    if sample and len(df) > sample:
        df = df.sample(sample, random_state=seed).reset_index(drop=True)
    for c in ["src_port", "dst_port"]:
        df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0).astype(int)
    df["service"] = df["service"].fillna("none").astype(str).replace({"-": "none", "nan": "none"})
    df["src_ip"] = df["src_ip"].astype(str)
    df["dst_ip"] = df["dst_ip"].astype(str)
    df["src_bytes"] = pd.to_numeric(df["src_bytes"], errors="coerce").fillna(0)
    df["type"] = df["type"].fillna("unknown").astype(str)
    return df[QIS + ["src_bytes", "type"]]


# ---------------------------------------------------------------- generalization hierarchies
def ip_gen(v, lvl):
    if lvl == 0:
        return v
    if lvl >= 4:
        return "*"
    parts = v.split(".")
    if len(parts) != 4:                               # IPv6 or unknown format
        return "ipv6/other"
    return ".".join(parts[:4 - lvl] + ["*"] * lvl)    # a.b.c.* / a.b.*.* / a.*.*.*


def port_gen(p, lvl):
    if lvl == 0:
        return str(p)
    if lvl == 1:
        return str(p) if p < 1024 else "1024+"
    if lvl == 2:
        return "well-known" if p < 1024 else ("registered" if p < 49152 else "dynamic")
    return "*"


def src_port_gen(p, lvl):
    if lvl == 0:
        return str(p)
    if lvl == 1:
        return f"{p // 1024 * 1024}-{p // 1024 * 1024 + 1023}"    # blocks of 1024 ports
    if lvl == 2:
        return "well-known" if p < 1024 else ("registered" if p < 49152 else "dynamic")
    return "*"


def service_gen(v, lvl):
    if lvl == 0:
        return v
    if lvl == 1:
        return "none" if v == "none" else "named"
    return "*"


def gen_col(df, qi, lvl):
    """Return the quasi-identifier `qi` generalized at level `lvl` (as strings)."""
    fn = {"src_ip": ip_gen, "dst_ip": ip_gen, "src_port": src_port_gen,
          "dst_port": port_gen, "service": service_gen}[qi]
    col = df[qi]
    mapping = {u: fn(u, lvl) for u in col.unique()}
    return col.map(mapping)


def gen_frame(df, levels):
    return pd.DataFrame({q: gen_col(df, q, levels[q]) for q in QIS}, index=df.index)


# ---------------------------------------------------------------- k-anonymity engine
class Anonymizer:
    def __init__(self, df):
        self.df = df
        self.n = len(df)
        self.tcodes, tuniq = pd.factorize(df[SENSITIVE])
        self.tcodes = self.tcodes.astype(np.int64)
        self.nt = len(tuniq)
        self.codes = {}
        for q in QIS:
            for lv in range(MAXLV[q] + 1):
                c, uniq = pd.factorize(gen_col(df, q, lv))
                self.codes[(q, lv)] = (c.astype(np.int64), len(uniq))

    def class_stats(self, levels, need_l=False):
        """per-record: size of its equivalence class and (optionally) #distinct sensitive values."""
        key = np.zeros(self.n, dtype=np.int64)
        for q in QIS:
            c, m = self.codes[(q, levels[q])]
            key = key * m + c
        ukey, inv, counts = np.unique(key, return_inverse=True, return_counts=True)
        sizes = counts[inv]
        if not need_l:
            return sizes, None
        pairs = np.unique(inv.astype(np.int64) * self.nt + self.tcodes)   # distinct (class, type)
        ldiv = np.bincount(pairs // self.nt, minlength=len(ukey))
        return sizes, ldiv[inv]

    def class_sizes(self, levels):
        return self.class_stats(levels)[0]

    @staticmethod
    def prec_loss(levels):
        return float(np.mean([levels[q] / MAXLV[q] for q in QIS]))

    def search(self, configs, max_supp):
        """Full-domain generalization: explore the whole lattice, keep for each (k, l) the node
        with minimal loss whose suppression rate is <= max_supp."""
        best = {c: None for c in configs}
        need_l = any(l > 1 for _, l in configs)
        for combo in itertools.product(*[range(MAXLV[q] + 1) for q in QIS]):
            levels = dict(zip(QIS, combo))
            sizes, ldiv = self.class_stats(levels, need_l)
            prec = self.prec_loss(levels)
            for (k, l) in configs:
                bad = sizes < k
                if l > 1:
                    bad = bad | (ldiv < l)
                supp = float(bad.mean())
                if supp > max_supp:
                    continue
                loss = (1 - supp) * prec + supp * 1.0
                if best[(k, l)] is None or loss < best[(k, l)]["loss"]:
                    best[(k, l)] = {"levels": levels, "supp": supp, "loss": loss, "prec": prec}
        top = {q: MAXLV[q] for q in QIS}
        for c in configs:
            if best[c] is None:
                best[c] = {"levels": top, "supp": 0.0, "loss": 1.0, "prec": 1.0}
        return best

    def release(self, levels, k, l=1):
        sizes, ldiv = self.class_stats(levels, l > 1)
        keep = sizes >= k
        if l > 1:
            keep = keep & (ldiv >= l)
        out = gen_frame(self.df, levels)
        out["src_bytes"] = self.df["src_bytes"].values
        out[SENSITIVE] = self.df[SENSITIVE].values
        return out[keep].reset_index(drop=True)


def release_metrics(rel, levels, k, n_orig, l=1):
    g = rel.groupby(QIS)
    sizes = g.size()
    ldiv = g[SENSITIVE].nunique()
    return {
        "k": k,
        "l": l,
        "levels": levels,
        "records_kept": int(len(rel)),
        "suppression_pct": round(100 * (1 - len(rel) / n_orig), 2),
        "precision_loss": round(Anonymizer.prec_loss(levels), 4),
        "equivalence_classes": int(len(sizes)),
        "avg_class_size": round(float(sizes.mean()), 2),
        "min_class_size": int(sizes.min()) if len(sizes) else 0,
        "min_l_diversity": int(ldiv.min()) if len(ldiv) else 0,
        "pct_records_in_homogeneous_classes": round(
            100 * float(sizes[ldiv == 1].sum()) / max(len(rel), 1), 2),
    }


# ---------------------------------------------------------------- linkage attack
def make_aux(df, n_aux, rng):
    """Second 'public' table: the attacker knows who (name) used which device (source IP),
    talking to which destination/ports/service (e.g. router log, leaked CSV).
    It contains NO sensitive attribute."""
    idx = rng.choice(len(df), size=min(n_aux, len(df)), replace=False)
    aux = df.iloc[idx][QIS].copy()
    aux["name"] = [f"Person_{i:04d}" for i in range(len(aux))]
    aux["_true_type"] = df.iloc[idx][SENSITIVE].values      # ground truth, for evaluation only
    return aux.reset_index(drop=True)


def linkage_attack(aux, released, levels):
    """Join aux with the released table on the (generalized) quasi-identifiers."""
    aux_g = gen_frame(aux, levels)
    aux_g["name"] = aux["name"]
    aux_g["_true_type"] = aux["_true_type"]
    grp = released.groupby(QIS)[SENSITIVE].agg(
        cand="size", ntypes="nunique", mode=lambda s: s.mode().iat[0] if len(s.mode()) else "unknown").reset_index()
    m = aux_g.merge(grp, on=QIS, how="left")
    m["cand"] = m["cand"].fillna(0).astype(int)
    unique = m["cand"] == 1
    inferred = (m["cand"] >= 1) & (m["ntypes"] == 1)
    correct = inferred & (m["mode"] == m["_true_type"])
    res = {
        "aux_size": int(len(m)),
        "reidentified_unique_pct": round(float(100 * unique.mean()), 2),
        "attribute_disclosed_pct": round(float(100 * inferred.mean()), 2),
        "attribute_disclosed_correct_pct": round(float(100 * correct.mean()), 2),
        "median_candidates": float(m.loc[m["cand"] > 0, "cand"].median()) if (m["cand"] > 0).any() else 0.0,
    }
    return res, m


# ---------------------------------------------------------------- differential privacy
def dp_grouped(gcodes, G, clipped, eps, B, rng):
    """eps-DP mean per group. Groups partition the records -> parallel composition.
    Budget per group: eps/2 for the sum (sensitivity B), eps/2 for the count (sensitivity 1)."""
    sums = np.bincount(gcodes, weights=clipped, minlength=G)
    cnts = np.bincount(gcodes, minlength=G).astype(float)
    noisy_s = sums + rng.laplace(0, B / (eps / 2), G)
    noisy_c = cnts + rng.laplace(0, 1 / (eps / 2), G)
    return noisy_s / np.maximum(noisy_c, 1.0), noisy_c


def dp_experiment(df, epsilons, trials, rng):
    gcodes, names = pd.factorize(df[DP_GROUP])
    G = len(names)
    B = float(df["src_bytes"].quantile(0.99))             # clipping bound (see README caveat)
    clipped = df["src_bytes"].clip(0, B).values
    sums = np.bincount(gcodes, weights=clipped, minlength=G)
    cnts = np.bincount(gcodes, minlength=G).astype(float)
    true_mean = sums / cnts
    rows = []
    for eps in epsilons:
        mae, rel, cmae = [], [], []
        for _ in range(trials):
            nm, nc = dp_grouped(gcodes, G, clipped, eps, B, rng)
            mae.append(np.abs(nm - true_mean).mean())
            rel.append(np.abs(nm - true_mean).sum() / max(true_mean.sum(), 1e-9))
            cmae.append(np.abs(nc - cnts).mean())
        rows.append({"epsilon": eps, "MAE_mean_bytes": float(np.mean(mae)),
                     "weighted_rel_error_pct": 100 * float(np.mean(rel)),
                     "MAE_count": float(np.mean(cmae))})
    raw_mean = np.bincount(gcodes, weights=df["src_bytes"].values, minlength=G) / cnts
    ctx = {"raw_mean": raw_mean, "gcodes": gcodes, "names": list(names), "G": G, "clipped": clipped, "cnts": cnts}
    return B, true_mean, ctx, pd.DataFrame(rows)


# ---------------------------------------------------------------- plots
def plot_anon(summary, raw_attack, attacks, out):
    x = ["raw"] + [f"k={s['k']}" + (f",l={s['l']}" if s["l"] > 1 else "") for s in summary]
    fig, ax = plt.subplots(1, 3, figsize=(17, 4.5))
    loss = [0] + [s["precision_loss"] for s in summary]
    supp = [0] + [s["suppression_pct"] / 100 for s in summary]
    ax[0].bar(x, loss, label="generalization loss (Prec)")
    ax[0].bar(x, supp, bottom=loss, label="suppressed records", alpha=.7)
    ax[0].set_title("Information loss vs k"); ax[0].set_ylabel("loss (0..1)"); ax[0].legend()
    ax[1].plot(x, [raw_attack["reidentified_unique_pct"]] + [a["reidentified_unique_pct"] for a in attacks],
               "o-", label="unique re-identification")
    ax[1].plot(x, [raw_attack["attribute_disclosed_correct_pct"]] + [a["attribute_disclosed_correct_pct"] for a in attacks],
               "s--", label="attack type correctly inferred")
    ax[1].set_title("Linkage attack success"); ax[1].set_ylabel("% of victims"); ax[1].legend()
    ax[2].bar(x[1:], [s["avg_class_size"] for s in summary])
    for a_ in ax:
        a_.tick_params(axis="x", labelrotation=30)
    ax[2].set_title("Average equivalence-class size"); ax[2].set_yscale("log")
    plt.tight_layout(); plt.savefig(out, dpi=140); plt.close()


def plot_dp(true_mean, ctx, B, rng, eps_main, res, out):
    fig, ax = plt.subplots(1, 2, figsize=(13, 4.2))
    x = np.arange(ctx["G"])
    w = 0.8 / (len(eps_main) + 1)
    ax[0].bar(x, true_mean, w, label="true mean", color="k")
    for i, e in enumerate(eps_main):
        nm, _ = dp_grouped(ctx["gcodes"], ctx["G"], ctx["clipped"], e, B, rng)
        ax[0].bar(x + (i + 1) * w, nm, w, label=f"eps={e}")
    ax[0].set_xticks(x + 0.4 - w / 2)
    ax[0].set_xticklabels([f"{n}\n(n={int(c)})" for n, c in zip(ctx["names"], ctx["cnts"])], fontsize=7)
    ax[0].set_ylabel("mean src_bytes (clipped)")
    ax[0].set_title(f"Mean per {DP_GROUP}: true vs DP answer (1 run)"); ax[0].legend()
    ax[1].loglog(res["epsilon"], res["MAE_mean_bytes"], "o-")
    ax[1].set_xlabel("epsilon (privacy loss, log)"); ax[1].set_ylabel("MAE of group mean (bytes, log)")
    ax[1].set_title("Error vs epsilon (avg of trials)"); ax[1].grid(True, which="both", alpha=.3)
    plt.tight_layout(); plt.savefig(out, dpi=140); plt.close()


def md_table(d):
    cols = list(d.columns)
    lines = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    for _, r in d.iterrows():
        lines.append("| " + " | ".join(str(r[c]) for c in cols) + " |")
    return "\n".join(lines)


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True, help="path to TON_IoT network CSV")
    ap.add_argument("--sample", type=int, default=150_000, help="max rows used (0 = all)")
    ap.add_argument("--ks", type=int, nargs="+", default=[2, 5, 10])
    ap.add_argument("--ls", type=int, nargs="+", default=[2, 3], help="extra l-diversity runs, applied with the largest k")
    ap.add_argument("--eps", type=float, nargs="+", default=[0.1, 1, 10])
    ap.add_argument("--max-suppress", type=float, default=0.05)
    ap.add_argument("--aux", type=int, default=500, help="victims in the attacker's auxiliary table")
    ap.add_argument("--trials", type=int, default=200)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default="outputs")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    rng = np.random.default_rng(a.seed)

    print("[1] loading ...")
    df = load_data(a.data, a.sample, a.seed)
    print(f"    {len(df)} records; QIs={QIS}; sensitive={SENSITIVE}")
    print("    classes of the sensitive attribute:", df[SENSITIVE].value_counts().to_dict())

    print("[2] linkage attack on the RAW data ...")
    zero = {q: 0 for q in QIS}
    raw_k = pd.Series(Anonymizer(df).class_sizes(zero))
    print(f"    raw data: {100 * (raw_k == 1).mean():.1f}% of records are unique on the QIs (k=1)")
    aux = make_aux(df, a.aux, rng)
    raw_attack, merged = linkage_attack(aux, gen_frame(df, zero).assign(**{SENSITIVE: df[SENSITIVE].values}), zero)
    print("    ", raw_attack)
    ex = merged[(merged.cand == 1)].head(10)[["name"] + QIS + ["mode"]]
    ex = ex.rename(columns={"mode": "REVEALED_type"})
    ex.to_csv(f"{a.out}/linkage_examples_raw.csv", index=False)
    print(ex.head(5).to_string(index=False))

    print("[3] k-anonymity (lattice search) ...")
    eng = Anonymizer(df)
    configs = [(k, 1) for k in a.ks] + [(max(a.ks), l) for l in a.ls]
    best = eng.search(configs, a.max_suppress)
    summary, attacks = [], []
    for (k, l) in configs:
        b = best[(k, l)]
        rel = eng.release(b["levels"], k, l)
        rel.to_csv(f"{a.out}/anonymized_k{k}_l{l}.csv", index=False)
        met = release_metrics(rel, b["levels"], k, len(df), l)
        att, _ = linkage_attack(aux, rel, b["levels"])
        met["attack"] = att
        summary.append(met); attacks.append(att)
        print(f"    k={k} l={l}: levels={b['levels']} suppressed={met['suppression_pct']}% "
              f"loss={met['precision_loss']} min-l={met['min_l_diversity']} attack={att}")

    print("[4] differential privacy ...")
    eps_grid = sorted(set(a.eps + [0.01, 0.05, 0.5, 5]))
    B, true_mean, ctx, dp_res = dp_experiment(df, eps_grid, a.trials, rng)
    print(f"    clipping bound B (99th pct of src_bytes) = {B:.0f}")
    print("    group | n | true mean (unclipped) | true mean (clipped, what DP estimates)")
    for nme, c, rm, tm in zip(ctx["names"], ctx["cnts"], ctx["raw_mean"], true_mean):
        print(f"    {nme:8s} {int(c):7d} {rm:14.1f} {tm:14.1f}")
    print(dp_res.round(3).to_string(index=False))
    dp_res.to_csv(f"{a.out}/dp_error_vs_epsilon.csv", index=False)

    print("[5] plots + summary ...")
    plot_anon(summary, raw_attack, attacks, f"{a.out}/fig_kanonymity_tradeoff.png")
    plot_dp(true_mean, ctx, B, rng, a.eps, dp_res, f"{a.out}/fig_dp_tradeoff.png")

    md = ["# Part A results (auto-generated)\n",
          f"Records: {len(df)} | QIs: {', '.join(QIS)} | sensitive: {SENSITIVE} | max suppression: {a.max_suppress:.0%}\n",
          "## k-anonymity vs linkage attack\n",
          "| release | levels (src_ip/dst_ip/src_port/dst_port/service) | suppressed % | Prec loss | classes | avg class | min l-div | unique re-id % | attack type inferred % |",
          "|---|---|---|---|---|---|---|---|---|",
          f"| raw | 0/0/0/0/0 | 0 | 0 | - | - | - | {raw_attack['reidentified_unique_pct']} | {raw_attack['attribute_disclosed_correct_pct']} |"]
    for s in summary:
        lv = "/".join(str(s["levels"][q]) for q in QIS)
        md.append(f"| k={s['k']}, l>={s['l']} | {lv} | {s['suppression_pct']} | {s['precision_loss']} | {s['equivalence_classes']} | "
                  f"{s['avg_class_size']} | {s['min_l_diversity']} | {s['attack']['reidentified_unique_pct']} | "
                  f"{s['attack']['attribute_disclosed_correct_pct']} |")
    md += ["\n## Differential privacy (mean of src_bytes per service, Laplace)\n", md_table(dp_res.round(3))]
    open(f"{a.out}/summary_part_a.md", "w").write("\n".join(md))
    json.dump({"raw_attack": raw_attack, "k_anonymity": summary, "clip_B": B,
               "dp_groups": {n: {"n": int(c), "mean_unclipped": float(r), "mean_clipped": float(t)}
                             for n, c, r, t in zip(ctx["names"], ctx["cnts"], ctx["raw_mean"], true_mean)}},
              open(f"{a.out}/results_part_a.json", "w"), indent=2, default=str)
    print(f"done -> {a.out}/")


if __name__ == "__main__":
    main()
