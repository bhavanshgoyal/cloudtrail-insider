"""
build_ieee_paper.py
-------------------
Generate every number and table of the IEEE paper from the result files, so nothing in the
paper is typed by hand, then compile it if a LaTeX engine (tectonic / pdflatex) is available.

  docs/paper_ieee/generated/numbers.tex     \\newcommand macros (dataset, main results, hypotheses)
  docs/paper_ieee/generated/tab_*.tex       tables
  docs/paper_ieee/figures/*.png             copies of the figures used
  docs/paper_ieee/main.pdf                  if a LaTeX engine is found

    python scripts/build_ieee_paper.py
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import zipfile
from pathlib import Path

import numpy as np
import pandas as pd
import yaml

PAPER = Path("docs/paper_ieee")
GEN = PAPER / "generated"
RES = Path("results")
PROPOSED = "proposed_budget_aware_conformal"
DET_ORDER = [PROPOSED, "isolation_forest", "lof", "autoencoder", "rule_baseline"]
DET_TEX = {PROPOSED: "BudgetAwareConformal (ours)", "isolation_forest": "Isolation Forest",
           "lof": "LOF", "autoencoder": "Autoencoder", "rule_baseline": "Rule signatures"}
FIGS = ["dr_vs_budget.png", "precision_vs_budget.png", "dr_by_scenario.png", "ablation.png",
        "auc_vs_dr10.png", "sweep_principals.png", "runtime_vs_principals.png"]
MISSING: list[str] = []


def _f(x, d=3) -> str:
    return "--" if x is None or not np.isfinite(x) else f"{x:.{d}f}"


def _pct(x, d=0) -> str:
    return "--" if x is None or not np.isfinite(x) else f"{100 * x:+.{d}f}\\%"


def _cmd(name: str, value: str) -> str:
    return f"\\newcommand{{\\{name}}}{{{value}}}\n"


def _csv(path: Path) -> pd.DataFrame | None:
    if path.exists():
        return pd.read_csv(path)
    MISSING.append(str(path))
    return None


def dataset_numbers() -> str:
    import pyarrow.parquet as pq

    feats = pd.read_parquet("data/cache/CERT_r4.2/features.parquet")
    labels = pd.read_parquet("data/cache/CERT_r4.2/labels.parquet")
    gt = json.loads(Path("data/cache/CERT_r4.2/ground_truth.json").read_text())
    n_events = sum(pq.ParquetFile(f"data/processed/cert_r4.2/{s}.parquet").metadata.num_rows
                   for s in ("logon", "device", "file", "email", "http"))
    sc = pd.Series([g["scenario_id"] for g in gt]).value_counts()
    out = [_cmd("NUsers", f"{feats['principal'].nunique():,}"), _cmd("NDays", str(feats['date'].nunique())),
           _cmd("NUserDays", f"{len(feats):,}"), _cmd("NEvents", f"{n_events / 1e6:.1f}"),
           _cmd("NInsiders", str(len(gt))), _cmd("NMalDays", f"{int(labels['label'].sum()):,}"),
           _cmd("PosRate", f"{100 * labels['label'].mean():.2f}"),
           _cmd("NFeatures", str(feats.shape[1] - 2))]
    for s in ("S1", "S2", "S3"):
        out.append(_cmd("NIns" + {"S1": "SOne", "S2": "STwo", "S3": "SThree"}[s], str(int(sc.get(s, 0)))))
    return "".join(out)


def main_results() -> str:
    s = _csv(RES / "campaign" / "summary.csv")
    h = _csv(RES / "campaign" / "hypotheses.csv")
    out = []
    if s is not None:
        def get(det, metric, b, field="mean"):
            r = s[(s.detector == det) & (s.metric == metric) & (s.budget == b)]
            return float(r[field].iloc[0]) if len(r) else np.nan

        letters = {PROPOSED: "Ours", "isolation_forest": "IF", "lof": "LOF", "autoencoder": "AE",
                   "rule_baseline": "Rules"}
        for det, L in letters.items():
            for b in (10, 50, 100):
                out.append(_cmd(f"DR{L}B{'ABC'[(10, 50, 100).index(b)]}", _f(get(det, "dr_at_b", b))))
                out.append(_cmd(f"P{L}B{'ABC'[(10, 50, 100).index(b)]}", _f(get(det, "precision_at_b", b))))
            out.append(_cmd(f"AUC{L}", _f(get(det, "auc_roc", 0))))
        out.append(_cmd("OracleP", _f(get(PROPOSED, "precision_oracle_at_b", 10))))
        out.append(_cmd("NInsTest", str(s[(s.metric == "dr_at_b") & (s.budget == 10)]["ci_unit"].iloc[0]
                                       .split("n=")[1].rstrip(")") if "ci_unit" in s else "--")))

        rows = []
        for det in DET_ORDER:
            cells = [DET_TEX[det]]
            for b in (10, 50, 100):
                m, lo, hi = (get(det, "dr_at_b", b, f) for f in ("mean", "ci_lo", "ci_hi"))
                cells.append(f"{_f(m, 2)} [{_f(lo, 2)}, {_f(hi, 2)}]")
            for b in (10, 50):
                cells.append(_f(get(det, "precision_at_b", b), 3))
            cells.append(_f(get(det, "mttd_hours_median", 10), 0))
            cells.append(_f(get(det, "auc_roc", 0), 3))
            if det == PROPOSED:
                cells = [f"\\textbf{{{c}}}" for c in cells]
            rows.append(" & ".join(cells) + r" \\")
        (GEN / "tab_main.tex").write_text("\n".join(rows) + "\n", encoding="utf-8")

    if h is not None and len(h):
        rows = []
        tex_name = {"H1a": "HypOneA", "H1b": "HypOneB", "H2": "HypTwo"}
        for r in h.itertuples(index=False):
            n = tex_name[r.hypothesis]
            out += [_cmd(f"{n}Verdict", r.verdict.lower()), _cmd(f"{n}Diff", _pct(r.diff)),
                    _cmd(f"{n}Lo", _pct(r.ci_lo)), _cmd(f"{n}Hi", _pct(r.ci_hi))]
            rows.append(f"{r.hypothesis} & {r.metric.replace('_', ' ').replace('@10', '')} & "
                        f"{_pct(r.threshold)} & {_f(r.proposed_mean, 3)} & {_f(r.baseline_mean, 3)} & "
                        f"{_pct(r.diff)} [{_pct(r.ci_lo)}, {_pct(r.ci_hi)}] & "
                        f"\\textsc{{{r.verdict.lower()}}} \\\\")
        (GEN / "tab_hyp.tex").write_text("\n".join(rows) + "\n", encoding="utf-8")
    return "".join(out)


def scenario_table() -> str:
    d = _csv(RES / "campaign" / "dr_by_scenario.csv")
    if d is None:
        return ""
    p = d.pivot_table(index="detector", columns="scenario_id", values="dr_at_10")
    n = d[d.detector == PROPOSED].set_index("scenario_id")["n"]
    head = " & ".join(f"{s} (n={int(n.get(s, 0))})" for s in p.columns)
    rows = [f"Detector & {head} \\\\ \\midrule"]
    for det in DET_ORDER:
        if det in p.index:
            rows.append(DET_TEX[det] + " & " + " & ".join(_f(p.loc[det, s], 2) for s in p.columns) + r" \\")
    (GEN / "tab_scenario.tex").write_text("\n".join(rows) + "\n", encoding="utf-8")
    word = {"S1": "SOne", "S2": "STwo", "S3": "SThree"}
    out = []
    for det, L in ((PROPOSED, "Ours"), ("isolation_forest", "IF"), ("lof", "LOF"), ("autoencoder", "AE"),
                   ("rule_baseline", "Rules")):
        if det in p.index:
            out += [_cmd(f"DR{L}{word[s]}", _f(p.loc[det, s], 2)) for s in p.columns]
    return "".join(out)


def ablation_table() -> str:
    a = _csv(RES / "ablation" / "ablation_summary.csv")
    if a is None:
        return ""
    a = a[a.budget == 10]
    rows = []
    first = ["Full (tuned)", "-C1 population baseline", "-C2 no calibration", "-C3 no fusion (pooled)"]
    variants = list(a["variant"].drop_duplicates())
    variants = ([v for v in first if v in variants] + sorted(v for v in variants if v not in first
                                                             and v != "isolation_forest")
                + (["isolation_forest"] if "isolation_forest" in variants else []))
    for v in variants:
        dr = a[(a.variant == v) & (a.metric == "dr_at_b")]
        p = a[(a.variant == v) & (a.metric == "precision_at_b")]
        name = "Isolation Forest (reference)" if v == "isolation_forest" else v.replace("_", r"\_")
        rows.append(f"{name} & {_f(dr['mean'].iloc[0], 2)} [{_f(dr['ci_lo'].iloc[0], 2)}, "
                    f"{_f(dr['ci_hi'].iloc[0], 2)}] & {_f(p['mean'].iloc[0], 3)} \\\\")
    (GEN / "tab_ablation.tex").write_text("\n".join(rows) + "\n", encoding="utf-8")
    names = {"Full (tuned)": "Full", "-C1 population baseline": "NoCOne", "-C2 no calibration": "NoCTwo",
             "-C3 no fusion (pooled)": "NoCThree", "+C4 suppress 3 d": "CFour", "-C4 no suppression": "CFour",
             "fusion: fisher": "Fisher", "fusion: min_p": "MinP", "fusion: harmonic": "Harmonic",
             "fusion: stouffer": "Stouffer", "-identity family": "NoIdentity", "-resource family": "NoResource",
             "-temporal family": "NoTemporal", "-volume family": "NoVolume"}
    out = []
    for v, n in names.items():
        for metric, L, d in (("dr_at_b", "DR", 2), ("precision_at_b", "P", 3)):
            r = a[(a.variant == v) & (a.metric == metric)]
            if len(r):
                out.append(_cmd(f"Abl{n}{L}", _f(float(r["mean"].iloc[0]), d)))
    return "".join(out)


def sweep_numbers() -> str:
    s = _csv(RES / "sweeps" / "sweeps_summary.csv")
    t = _csv(RES / "sweeps" / "scale_timing.csv")
    out = []
    L = {PROPOSED: "Ours", "isolation_forest": "IF", "lof": "LOF", "autoencoder": "AE", "rule_baseline": "Rules"}
    if s is not None:
        p = s[(s.sweep == "principals") & (s.budget == 10) & (s.metric == "dr_at_b")]
        xs = sorted(p["x"].unique())
        word = {xs[0]: "Small", xs[1]: "Mid", xs[-1]: "Full"} if len(xs) >= 3 else {}
        for x, w in word.items():
            out.append(_cmd(f"NUsers{w}", f"{int(x):,}"))
            for det, l in L.items():
                r = p[(p.x == x) & (p.detector == det)]
                if len(r):
                    out.append(_cmd(f"DRSweep{l}{w}", _f(float(r["mean"].iloc[0]), 2)))
    if t is not None:
        full = t[t["sweep_n"] == t["sweep_n"].max()].groupby("detector")["fit_score_seconds"].mean()
        for det, l in L.items():
            if det in full:
                out.append(_cmd(f"Secs{l}", f"{full[det]:.1f}"))
    return "".join(out)


def tuned_settings() -> str:
    p = Path("configs/proposed_final.yaml")
    if not p.exists():
        MISSING.append(str(p))
        return ""
    prop = yaml.safe_load(p.read_text())["detectors"]["proposed"]
    log = _csv(RES / "tuning_log.csv")
    val = []
    if log is not None:
        bestp = log[log.detector == "proposed"].sort_values(["val_dr_at_10", "val_p_at_10"]).iloc[-1]
        besti = log[log.detector == "isolation_forest"].sort_values(["val_dr_at_10", "val_p_at_10"]).iloc[-1]
        val = [_cmd("ValDROurs", _f(bestp["val_dr_at_10"], 3)), _cmd("ValPOurs", _f(bestp["val_p_at_10"], 3)),
               _cmd("ValDRIF", _f(besti["val_dr_at_10"], 3)), _cmd("ValPIF", _f(besti["val_p_at_10"], 3)),
               _cmd("NTuningConfigs", str(len(log)))]
    fus = {"fisher": "Fisher", "min_p": "Bonferroni min-$p$", "harmonic": "harmonic-mean $p$",
           "stouffer": "Stouffer"}[prop["fusion"]]
    return "".join([_cmd("TunedFusion", fus), _cmd("TunedAgg", prop["family_agg"].upper()),
                    _cmd("TunedSuppress", str(prop["suppress_days"])),
                    _cmd("TunedCal", str(prop["cal_fraction"])), _cmd("TunedShrink", str(prop["shrink_k"])),
                    _cmd("TunedAlpha", str(prop["scale_alpha"])),
                    _cmd("TunedTransform", "$\\log(1+x)$" if prop["transform"] == "log1p" else "identity"),
                    *val])


def triage_numbers() -> str:
    out = []
    e = RES / "explanations" / "summary.json"
    if e.exists():
        s = json.loads(e.read_text())
        prec = s["precision_by_primary_family"]
        out += [_cmd("ExpNAlerts", f"{s['n_alerts']:,}"), _cmd("ExpNTrue", str(s["n_true"])),
                _cmd("ExpVolPrec", f"{100 * prec.get('volume', 0):.1f}"),
                _cmd("ExpResPrec", f"{100 * prec.get('resource', 0):.1f}"),
                _cmd("ExpTmpPrec", f"{100 * prec.get('temporal', 0):.1f}"),
                _cmd("ExpIdnPrec", f"{100 * prec.get('identity', 0):.1f}"),
                _cmd("ExpVolShareTrue", f"{100 * s['share_true_explained_by'].get('volume', 0):.0f}"),
                _cmd("ExpAllPrec", f"{100 * s['n_true'] / s['n_alerts']:.1f}")]
    else:
        MISSING.append(str(e))
    sh = RES / "shap_crosscheck.json"
    if sh.exists():
        s = json.loads(sh.read_text())
        out += [_cmd("ShapN", str(s["n"])), _cmd("ShapTopNamed", f"{100 * s['top1_in_named']:.0f}"),
                _cmd("ShapFamilyAgree", f"{100 * s['family_agreement']:.0f}")]
    else:
        MISSING.append(str(sh))
    meta = Path("docs/triage_study/study_meta.json")
    if meta.exists():
        m = json.loads(meta.read_text())
        out += [_cmd("StudyN", str(m["n_alerts"])), _cmd("StudyTrue", str(m["n_tp"])),
                _cmd("StudyFalse", str(m["n_alerts"] - m["n_tp"]))]
        key = pd.read_csv("docs/triage_study/_facilitator_only/answer_key.csv")
        out.append(_cmd("StudyInsiders", str(key.loc[key["true_label"] == "TP", "principal"].nunique())))
    t = RES / "triage_results.json"
    out.append(_cmd("TriageStatus", "complete" if t.exists() else "pending: the four reviewers have not yet "
                    "completed it, so H3 is untested"))
    if t.exists():
        r = json.loads(t.read_text())
        h, arms = r["h3"], r["arms"]
        pp = lambda x: f"{100 * x:+.1f}"
        out += [_cmd("TriageVerdict", h["verdict"].lower()), _cmd("TriageDiff", pp(h["effect_ba_B_minus_A"])),
                _cmd("TriageLo", pp(h["ci_lo"])), _cmd("TriageHi", pp(h["ci_hi"])),
                _cmd("TriageThr", f"{100 * h['threshold']:.0f}"),
                _cmd("TriageNUsable", str(r["completeness"]["usable"])),
                _cmd("TriageNExpected", str(r["completeness"]["expected_judgements"])),
                _cmd("TriageNExcluded", str(r["completeness"]["expected_judgements"] - r["completeness"]["usable"]))]
        rows = []
        for arm, L, name in (("A", "A", "Score only"), ("B", "B", "Explanation only")):
            s = arms[arm]
            out += [_cmd(f"TriageBA{L}", _f(s["balanced_accuracy"], 3)), _cmd(f"TriageSens{L}", _f(s["sensitivity"], 2)),
                    _cmd(f"TriageSpec{L}", _f(s["specificity"], 2)), _cmd(f"TriageN{L}", str(s["n_judgements"]))]
            rows.append(f"{name} & {s['n_judgements']} & {_f(s['balanced_accuracy'], 3)} & {_f(s['sensitivity'], 2)} & "
                        f"{_f(s['specificity'], 2)} & {s['mean_confidence']:.1f} & {s['mean_seconds']:.0f} \\\\")
        (GEN / "tab_triage.tex").write_text("\n".join(rows) + "\n", encoding="utf-8")
        short = [f"{k.split('-')[0]} ({20 - v['n_judgements']} in arm {k.split('-')[1]})"
                 for k, v in r["per_reviewer"].items() if v["n_judgements"] < 20]
        out.append(_cmd("TriageExcludedWho", ", ".join(short) if short else "none"))
        kb = [k for k in r["kappa"] if k["n"] >= 10]
        out.append(_cmd("TriageKappas", "; ".join(f"{k['pair']} arm {k['arm']} {k['kappa']:.2f}" for k in kb)))
        fam = r["arm_B_accuracy_by_family"]
        for f, L in (("identity", "Idn"), ("resource", "Res"), ("temporal", "Tmp"), ("volume", "Vol")):
            if f in fam:
                out.append(_cmd(f"TriageFam{L}", f"{fam[f]['accuracy']:.2f} (n={fam[f]['n']})"))
    return "".join(out)


CUSTOM = re.compile(r"\\((?:DR|P|AUC|Hyp|N|Tuned|Oracle|PosRate|Triage|DROurs|Abl|Val|MTTD|Exp|Shap|Study|Secs|NUsers)[A-Za-z]*)\b")


def check_tex() -> list[str]:
    """Static checks that stand in for a compiler: macros defined, inputs present, braces, citations."""
    problems = []
    defined = set(re.findall(r"\\newcommand\{\\([A-Za-z]+)\}", (GEN / "numbers.tex").read_text()))
    defined |= set(re.findall(r"\\newcommand\{\\([A-Za-z]+)\}", (PAPER / "main.tex").read_text()))
    bib = set(re.findall(r"@\w+\{([^,]+),", (PAPER / "references.bib").read_text(encoding="utf-8")))
    files = [PAPER / "main.tex", *sorted((PAPER / "sections").glob("*.tex"))]
    for f in files:
        t = re.sub(r"(?<!\\)%.*", "", f.read_text(encoding="utf-8"))
        for m in sorted(set(CUSTOM.findall(t)) - defined):
            problems.append(f"{f.name}: undefined macro \\{m}")
        for inp in re.findall(r"\\input\{([^}]+)\}", t):
            if not (PAPER / inp).exists():
                problems.append(f"{f.name}: \\input{{{inp}}} missing")
        for keys in re.findall(r"\\cite\{([^}]+)\}", t):
            problems += [f"{f.name}: unknown citation {k}" for k in keys.split(",") if k.strip() not in bib]
        for fig in re.findall(r"\\includegraphics(?:\[[^\]]*\])?\{([^}]+)\}", t):
            if not (PAPER / fig).exists():
                problems.append(f"{f.name}: figure {fig} missing")
        depth = 0
        for ch in re.sub(r"\\[{}]", "", t):
            depth += (ch == "{") - (ch == "}")
            if depth < 0:
                break
        if depth != 0:
            problems.append(f"{f.name}: unbalanced braces ({depth:+d})")
        if t.count(r"\begin{") != t.count(r"\end{"):
            problems.append(f"{f.name}: {t.count(chr(92) + 'begin{')} \\begin vs {t.count(chr(92) + 'end{')} \\end")
    return problems


def overleaf_zip() -> Path:
    out = PAPER.parent / "paper_ieee_overleaf.zip"
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for f in PAPER.rglob("*"):
            if f.is_file() and f.suffix in {".tex", ".bib", ".png", ".bst", ".cls"}:
                z.write(f, f.relative_to(PAPER))
    return out


def compile_pdf() -> None:
    for engine, args in (("tectonic", ["tectonic", "-X", "compile", "main.tex"]),
                         ("pdflatex", None)):
        exe = shutil.which(engine) or (str(Path("tools/tectonic.exe").resolve())
                                       if engine == "tectonic" and Path("tools/tectonic.exe").exists() else None)
        if not exe:
            continue
        if engine == "tectonic":
            cmd = [exe, "-X", "compile", "main.tex"]
            r = subprocess.run(cmd, cwd=PAPER, capture_output=True, text=True)
        else:
            r = None
            for cmd in (["pdflatex", "-interaction=nonstopmode", "main.tex"], ["bibtex", "main"],
                        ["pdflatex", "-interaction=nonstopmode", "main.tex"],
                        ["pdflatex", "-interaction=nonstopmode", "main.tex"]):
                r = subprocess.run(cmd, cwd=PAPER, capture_output=True, text=True)
        if r.returncode == 0:
            print(f"compiled {PAPER / 'main.pdf'} with {engine}")
        else:
            print(f"{engine} failed:\n{(r.stdout + r.stderr)[-3000:]}")
        return
    print("no LaTeX engine found: upload docs/paper_ieee/ to Overleaf (it compiles as-is)")


def main() -> None:
    GEN.mkdir(parents=True, exist_ok=True)
    (PAPER / "figures").mkdir(exist_ok=True)
    tex = ("% generated by scripts/build_ieee_paper.py - do not edit\n" + dataset_numbers() + main_results()
           + scenario_table() + ablation_table() + sweep_numbers() + tuned_settings() + triage_numbers())
    (GEN / "numbers.tex").write_text(tex, encoding="utf-8")
    for f in FIGS:
        src = Path("figures") / f
        if src.exists():
            shutil.copy(src, PAPER / "figures" / f)
        else:
            MISSING.append(str(src))
    shutil.copy("docs/references.bib", PAPER / "references.bib")
    print(f"wrote {GEN}/ ({tex.count(chr(10))} macros)")
    if MISSING:
        print("MISSING inputs (their numbers/tables are absent):\n  " + "\n  ".join(MISSING))
    problems = check_tex()
    print("LaTeX checks: " + ("OK" if not problems else "\n  " + "\n  ".join(problems)))
    print(f"Overleaf upload: {overleaf_zip()}")
    compile_pdf()


if __name__ == "__main__":
    main()
