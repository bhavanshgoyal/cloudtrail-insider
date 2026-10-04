"""
cti.demo.app
------------
Streamlit dashboard: the analyst's view of one run of ``python run_pipeline.py``.

  * pick a detector, a day and a budget -> that day's alert queue
  * for the proposed detector, the generated explanation of each alert (O3)
  * campaign results (all workloads x 5 seeds) with confidence intervals

Run with::

    python run_pipeline.py          # produces results/scores.parquet, explanations.json, metrics.csv
    streamlit run src/cti/demo/app.py
"""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import streamlit as st

from cti.eval.evaluate import emit_alerts
from cti.explain.explain_proposed import FAMILY_TEXT, render

RESULTS = Path("results")
PROPOSED = "proposed_budget_aware_conformal"
NAMES = {PROPOSED: "Proposed (BudgetAwareConformal)", "isolation_forest": "Isolation Forest", "lof": "LOF",
         "autoencoder": "Autoencoder", "rule_baseline": "Rule signatures"}

st.set_page_config(page_title="CloudTrail insider-threat queue", layout="wide")


@st.cache_data(show_spinner=False)
def load():
    scores = pd.read_parquet(RESULTS / "scores.parquet")
    scores["date"] = pd.to_datetime(scores["date"])
    metrics = pd.read_csv(RESULTS / "metrics.csv")
    expl = json.loads((RESULTS / "explanations.json").read_text())
    campaign = RESULTS / "campaign" / "summary.csv"
    return scores, metrics, expl, (pd.read_csv(campaign) if campaign.exists() else None)


def main() -> None:
    if not (RESULTS / "scores.parquet").exists():
        st.error("No results yet. Run `python run_pipeline.py` first.")
        return
    scores, metrics, expl, campaign = load()
    by_key = {(e["principal"], e["date"]): e for e in expl["alerts"]}

    st.title("CloudTrail insider-threat alert queue")
    st.caption(f"One run: workload {expl['workload']}, seed {expl['seed']}, rolling origin {expl['origin']}, "
               "test window only. Detector settings frozen on validation data.")

    with st.sidebar:
        det = st.selectbox("Detector", list(NAMES), format_func=NAMES.get)
        budget = st.select_slider("Alerts per day (budget)", options=[1, 5, 10, 20, 50, 100], value=10)
        days = sorted(scores["date"].unique())
        day = st.select_slider("Day", options=days, value=days[0], format_func=lambda d: str(d)[:10])

    tab_queue, tab_metrics, tab_campaign = st.tabs(["Today's queue", "This run's metrics", "Campaign (5 seeds)"])

    with tab_queue:
        s = scores[scores["detector"] == det]
        al = emit_alerts(s, budget, 0, int(expl["seed"]))
        today = al[al["date"] == day]
        st.subheader(f"{NAMES[det]}: {len(today)} alerts on {str(day)[:10]}")
        if today.empty:
            st.info("This detector raised no alert that day.")
        for _, a in today.iterrows():
            with st.container(border=True):
                st.markdown(f"**#{int(a['rank'])}  {a['principal']}**  ·  score {a['score']:.2f}")
                e = by_key.get((a["principal"], str(day)[:10])) if det == PROPOSED else None
                if e:
                    st.code(render(e), language=None)
                    pv = pd.Series(e["family_pvalues"]).rename(index=lambda f: FAMILY_TEXT.get(f, f))
                    st.caption("How unusual each behaviour family is for this identity (smaller p = more unusual)")
                    st.dataframe(pv.rename("p-value").to_frame().T, hide_index=True)
                elif det == PROPOSED:
                    st.caption("Explanation stored for the 10-alerts/day queue only; set the budget to 10.")
                else:
                    st.caption("This baseline gives a score but no explanation.")

    with tab_metrics:
        show = metrics[metrics["metric"].isin(["dr_at_b", "precision_at_b", "precision_oracle_at_b",
                                               "mttd_hours_median"]) & (metrics["budget"] > 0)]
        st.dataframe(show.pivot_table(index="detector", columns=["metric", "budget"], values="value")
                     .rename(index=NAMES).round(3))
        st.caption("Single run; see the Campaign tab for means and 95% CIs over seeds.")

    with tab_campaign:
        if campaign is None:
            st.info("Run `python scripts/run_campaign.py` for multi-seed results.")
        else:
            m = st.radio("Metric", ["dr_at_b", "precision_at_b"], horizontal=True,
                         format_func={"dr_at_b": "Detection rate", "precision_at_b": "Precision"}.get)
            c = campaign[(campaign["metric"] == m) & (campaign["budget"] == 10)].copy()
            c["value"] = c.apply(lambda r: f"{r['mean']:.3f}  [{r['ci_lo']:.3f}, {r['ci_hi']:.3f}]", axis=1)
            st.dataframe(c.pivot(index="detector", columns="workload", values="value").rename(index=NAMES))
            for fig in ("per_workload_dr10.png", "precision_vs_budget.png", "ablation.png"):
                if (Path("figures") / fig).exists():
                    st.image(str(Path("figures") / fig))


if __name__ == "__main__":
    main()
