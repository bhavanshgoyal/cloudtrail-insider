"""
cti.explain.explain_proposed
----------------------------
Alert explanations for the proposed detector (objective O3) and a SHAP
cross-check of their faithfulness.

An explanation names the behavioural deviation responsible for the alert:

    Resource access deviation (p = 0.0004)
      - USB device connections outside 08:00-18:00: 3 (usually 0)
      - visits to leak / file-upload sites: 2 (usually 0)
    Also unusual: timing

It is built from the detector's own per-feature attribution (one-sided robust
z-scores against the principal's history, grouped into the family with the
lowest conformal p-value). It never uses labels or scenario ids.

``shap_crosscheck`` asks an independent attribution method (Kernel SHAP on
the detector's final score, baseline = the principal's usual behaviour)
whether the feature it ranks first is one the explanation names.
"""
from __future__ import annotations

import logging

import numpy as np
import pandas as pd

log = logging.getLogger(__name__)

FAMILY_TEXT = {
    "identity": "Identity / access-origin deviation",
    "resource": "Resource access deviation",
    "temporal": "Timing deviation",
    "volume": "Activity volume deviation",
}

# feature -> (description, format)   format: int | pct | hours | float | bytes
FEATURE_TEXT = {
    "idn_unique_pcs": ("distinct PCs used", "int"),
    "idn_new_pcs": ("PCs this user has never used before", "int"),
    "idn_logons_new_pc": ("logons on a PC this user has never used before", "int"),
    "res_usb_connects": ("USB device connections", "int"),
    "res_usb_after_hours": ("USB device connections outside 08:00-18:00", "int"),
    "res_usb_first_use": ("first USB device use ever by this user", "int"),
    "res_exe_files": ("executable files copied to removable media", "int"),
    "res_job_site_visits": ("visits to job-search sites", "int"),
    "res_leak_site_visits": ("visits to leak / file-upload sites", "int"),
    "res_email_external": ("emails sent outside the company", "int"),
    "res_email_external_attach": ("emails with attachments sent outside the company", "int"),
    "res_email_ext_recipients": ("external email recipients", "int"),
    "rar_rare_domain_visits": ("visits to websites almost nobody in the company has visited", "int"),
    "rar_rare_domain_frac": ("share of web visits to rarely-visited websites", "pct"),
    "tmp_after_hours_ratio": ("share of activity outside 08:00-18:00", "pct"),
    "tmp_after_hours_logons": ("logons outside 08:00-18:00", "int"),
    "tmp_hour_deviation": ("hours away from this user's usual working time", "hours"),
    "tmp_weekend_events": ("activity at the weekend", "int"),
    "tmp_active_hours": ("distinct hours with activity", "int"),
    "vol_events": ("logged actions", "int"),
    "vol_logons": ("logons", "int"),
    "vol_http": ("web page visits", "int"),
    "vol_emails": ("emails sent", "int"),
    "vol_email_log_bytes": ("email data sent", "bytes"),
    "vol_file_copies": ("files copied to removable media", "int"),
    "div_unique_domains": ("distinct websites visited", "int"),
    "div_new_domains": ("websites this user has never visited before", "int"),
}


def _fmt(v: float, kind: str) -> str:
    if kind == "pct":
        return f"{100 * v:.0f}%"
    if kind == "hours":
        return f"{v:.1f} h"
    if kind == "float":
        return f"{v:.1f}"
    if kind == "bytes":
        b = float(np.expm1(v))
        for unit in ("B", "KB", "MB", "GB"):
            if b < 1024:
                return f"{b:.0f} {unit}"
            b /= 1024
        return f"{b:.1f} TB"
    return f"{v:.0f}"


def render(expl: dict) -> str:
    """Plain-language explanation text for one alert."""
    fam = expl["primary_family"]
    p = expl["family_pvalues"][fam]
    lines = [f"{FAMILY_TEXT.get(fam, fam)} (p = {p:.2g})"]
    for f in expl["top_features"]:
        desc, kind = FEATURE_TEXT.get(f["feature"], (f["feature"].replace("_", " "), "float"))
        usual_kind = "float" if kind == "int" and abs(f["usual"] - round(f["usual"])) > 0.05 else kind
        lines.append(f"  - {desc}: {_fmt(f['value'], kind)} (usually {_fmt(f['usual'], usual_kind)})")
    if len(lines) == 1:
        lines.append("  - no single feature stands out; several small deviations combined")
    if expl.get("secondary_families"):
        lines.append("Also unusual: " + ", ".join(FAMILY_TEXT.get(s, s).split(" deviation")[0].lower()
                                                 for s in expl["secondary_families"]))
    return "\n".join(lines)


def explain_alerts(detector, df_rows: pd.DataFrame, top_k: int = 3) -> list[dict]:
    """Structured explanation + rendered text for every row of ``df_rows``."""
    out = detector.explain(df_rows, top_k=top_k)
    for e in out:
        e["text"] = render(e)
    return out


def shap_crosscheck(detector, df_rows: pd.DataFrame, explanations: list[dict], n: int = 30,
                    nsamples: int = 1000, seed: int = 0) -> dict:
    """Kernel SHAP on the detector score vs. the explanation's named features.

    For each sampled alert the SHAP baseline is the principal's usual feature
    vector (the explanation's own reference point), so both methods answer
    "what differs from this identity's normal day".
    """
    import shap

    rng = np.random.default_rng(seed)
    idx = rng.choice(len(df_rows), size=min(n, len(df_rows)), replace=False)
    cols = detector.feat_cols
    per_alert = []
    for i in idx:
        row = df_rows.iloc[[i]]
        principal = row["principal"].iloc[0]
        k = detector._lookup(np.array([principal]))[0]
        background = detector._inv_t(detector._med[k] if k >= 0 else detector._pop_med)[None, :]

        def f(X, principal=principal):
            df = pd.DataFrame(X, columns=cols)
            df["principal"] = principal
            return detector.score(df)

        explainer = shap.KernelExplainer(f, background)
        sv = np.asarray(explainer.shap_values(row[cols].to_numpy(dtype=float), nsamples=nsamples,
                                              silent=True)).reshape(-1)
        top_shap = cols[int(np.argmax(sv))]
        named = [t["feature"] for t in explanations[i]["top_features"]]
        fam_of = {c: fam for fam in detector.families for c in np.array(cols)[detector._fam_idx[fam]]}
        per_alert.append(dict(principal=principal, date=explanations[i]["date"], shap_top=top_shap,
                              shap_top_family=fam_of[top_shap], named=named,
                              primary_family=explanations[i]["primary_family"],
                              top1_in_named=top_shap in named,
                              family_agrees=fam_of[top_shap] == explanations[i]["primary_family"]))
    df = pd.DataFrame(per_alert)
    return dict(n=len(df), top1_in_named=float(df["top1_in_named"].mean()) if len(df) else np.nan,
                family_agreement=float(df["family_agrees"].mean()) if len(df) else np.nan,
                per_alert=per_alert)
