"""
cti.demo.app
------------
Streamlit dashboard for the cloudtrail-insider project.

Shows:
- Live alert feed at configurable budget B
- SHAP explanation waterfall for a selected alert
- Precision@B / Recall@B trend chart across detectors

Run with:
    streamlit run src/cti/demo/app.py
"""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import streamlit as st

from cti.util.config import load_config
from cti.util.seeds import set_all_seeds

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="CloudTrail Insider Threat",
    page_icon="🔍",
    layout="wide",
)


@st.cache_data(show_spinner=False)
def _load_config():
    cfg = load_config()
    set_all_seeds(cfg["random_seed"])
    return cfg


@st.cache_data(show_spinner=False)
def _load_scores(path: str) -> pd.DataFrame:
    return pd.read_parquet(path)


@st.cache_data(show_spinner=False)
def _load_metrics(path: str) -> pd.DataFrame:
    return pd.read_parquet(path)


@st.cache_data(show_spinner=False)
def _load_shap_alerts(path: str) -> list[dict]:
    with open(path) as fh:
        data = json.load(fh)
    return data.get("alerts", [])


def main() -> None:
    """Streamlit app entrypoint."""
    cfg   = _load_config()
    demo  = cfg["demo"]
    paths = cfg["paths"]

    st.title("🔍 CloudTrail Insider Threat Dashboard")
    st.caption("Fixed-budget anomaly detection over AWS CloudTrail logs")

    # ── Sidebar controls ──────────────────────────────────────────────────────
    with st.sidebar:
        st.header("Controls")
        budget = st.selectbox(
            "Alert Budget (B)",
            options=cfg["budgets"],
            index=cfg["budgets"].index(demo["default_budget"])
            if demo["default_budget"] in cfg["budgets"]
            else 0,
        )
        detector_name = st.selectbox(
            "Detector",
            options=["isolation_forest", "lof", "autoencoder"],
        )

    results_dir = Path(paths["results_dir"])

    # ── Alert feed ────────────────────────────────────────────────────────────
    st.header(f"Top-{budget} Alerts  ·  {detector_name}")

    score_files = list(results_dir.glob("**/scores.parquet"))
    if not score_files:
        st.warning("No scores found. Run `make baselines proposed` first.")
        return

    df_scores = _load_scores(str(score_files[-1]))
    det_scores = df_scores[df_scores.get("detector", pd.Series()) == detector_name].copy()
    if det_scores.empty:
        det_scores = df_scores.copy()

    det_scores = det_scores.sort_values("score", ascending=False).head(budget)
    st.dataframe(
        det_scores[["principal", "date", "score"]].reset_index(drop=True),
        use_container_width=True,
    )

    # ── Metrics trend ─────────────────────────────────────────────────────────
    st.header("Evaluation Metrics")

    metric_files = list(results_dir.glob("**/metrics.parquet"))
    if metric_files:
        df_metrics = _load_metrics(str(metric_files[-1]))
        df_plot = df_metrics[
            (df_metrics["metric"] == "precision_at_b") & (df_metrics["budget"] == budget)
        ].set_index("detector")[["value"]]
        st.bar_chart(df_plot, y="value")
    else:
        st.info("No evaluation metrics found yet.")

    # ── SHAP explanations ─────────────────────────────────────────────────────
    st.header("SHAP Explanations")

    shap_files = list(results_dir.glob("**/shap_alerts.json"))
    if shap_files:
        alerts = _load_shap_alerts(str(shap_files[-1]))
        if alerts:
            alert_labels = [f"#{a['rank']}  {a['principal']}  {a['date']}" for a in alerts]
            sel = st.selectbox("Select alert", alert_labels)
            idx = alert_labels.index(sel)
            chosen = alerts[idx]

            shap_df = (
                pd.DataFrame.from_dict(
                    chosen["shap"], orient="index", columns=["shap_value"]
                )
                .sort_values("shap_value", key=abs, ascending=False)
                .head(cfg["explain"]["shap_max_display"])
            )
            st.bar_chart(shap_df["shap_value"])
            st.json({"principal": chosen["principal"], "date": chosen["date"], "score": chosen["score"]})
    else:
        st.info("No SHAP explanations found. Run `make explain` first.")

    st.divider()
    st.caption("cloudtrail-insider  ·  research prototype")


if __name__ == "__main__":
    main()
