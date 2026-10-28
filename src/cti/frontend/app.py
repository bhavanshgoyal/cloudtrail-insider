"""
cti.frontend.app
----------------
Analyst console: upload CERT-format audit logs, run the frozen detector, triage the daily queue.

    python scripts/train_final_model.py        # once: fit + save models/cert_model.pkl
    streamlit run src/cti/frontend/app.py
"""
from __future__ import annotations

import io
import json
from pathlib import Path

import pandas as pd
import streamlit as st

from cti.explain.explain_proposed import FAMILY_TEXT
from cti.features.cert import SOURCES
from cti.inference import MODEL_PATH, PROPOSED, analyse, detect_source, evaluate_upload, load_model, read_csv_upload
from cti.util.config import load_config

st.set_page_config(page_title="Insider-Threat Analyst Console", page_icon=":mag:", layout="wide")

NAMES = {PROPOSED: "Proposed (BudgetAwareConformal)", "isolation_forest": "Isolation Forest", "lof": "LOF",
         "autoencoder": "Autoencoder", "rule_baseline": "Rule signatures"}
FAMILY_SHORT = {"identity": "Identity", "resource": "Resource", "temporal": "Timing", "volume": "Volume"}
COLUMNS_HELP = {
    "logon": "id, date, user, pc, activity (Logon / Logoff)",
    "device": "id, date, user, pc, activity (Connect / Disconnect)",
    "file": "id, date, user, pc, filename, content",
    "email": "id, date, user, pc, to, cc, bcc, from, size, attachments, content",
    "http": "id, date, user, pc, url, content",
}
RESULTS = Path("results")
FIGURES = Path("figures")


@st.cache_resource(show_spinner="Loading the trained model ...")
def _model():
    return load_model(MODEL_PATH)


@st.cache_data(show_spinner=False)
def _cfg():
    return load_config()


def _parse_uploads(files) -> tuple[dict[str, pd.DataFrame], list[str], pd.DataFrame | None]:
    cfg = _cfg()
    frames, notes, labels = {}, [], None
    for f in files:
        data = f.getvalue()
        if Path(f.name).stem.lower().startswith("label"):
            labels = pd.read_csv(io.BytesIO(data))
            if not {"user", "date"} <= set(labels.columns):
                raise ValueError(f"{f.name}: a labels file needs columns user, date")
            notes.append(f"{f.name}: labels for {labels['user'].nunique()} users (used only for scoring the run)")
            continue
        src = detect_source(f.name, data)
        if src is None:
            raise ValueError(f"{f.name}: not recognised as one of {', '.join(SOURCES)} "
                             "(name the file e.g. http.csv, or use the CERT r4.2 columns)")
        df = read_csv_upload(data, src, cfg)
        frames[src] = pd.concat([frames[src], df], ignore_index=True) if src in frames else df
        notes.append(f"{f.name}: {src}, {len(df):,} events, {df['user'].nunique()} users")
    return frames, notes, labels


def _family_chart(alerts: pd.DataFrame) -> pd.DataFrame:
    return (alerts["primary_family"].map(FAMILY_SHORT).value_counts()
            .rename_axis("Most unusual behaviour").rename("Alerts").to_frame())


def page_upload() -> None:
    st.subheader("1. Upload audit logs")
    st.markdown(
        "Upload one or more **CERT r4.2-format CSV files** (any of logon, device, file, email, http) "
        "covering at least a few weeks. Add an optional `labels.csv` (columns `user,date`) to see how "
        "many malicious user-days the detectors catch.")
    with st.expander("Expected columns"):
        st.table(pd.Series(COLUMNS_HELP, name="columns").rename_axis("file"))
    files = st.file_uploader("CSV files", type=["csv"], accept_multiple_files=True)

    c1, c2 = st.columns(2)
    budget = c1.select_slider("Alert budget (alerts an analyst reviews per day)",
                              options=[1, 2, 5, 10, 20, 50, 100], value=10)
    history = c2.number_input("History days (used as each user's past, not scored)", 7, 60, 14)

    if st.button("Run detection", type="primary", disabled=not files):
        try:
            with st.spinner("Parsing uploads ..."):
                frames, notes, labels = _parse_uploads(files)
            if not frames:
                raise ValueError("no log files uploaded (only labels)")
            with st.spinner("Building behaviour features and scoring every user-day ..."):
                an = analyse(frames, _model(), _cfg(), budget=budget, history_days=int(history))
        except ValueError as e:
            st.error(str(e))
            return
        st.session_state.update(an=an, notes=notes, labels=labels, budget=budget,
                                n_events=sum(len(f) for f in frames.values()))

    an = st.session_state.get("an")
    if an is None:
        return
    for n in st.session_state["notes"]:
        st.caption(n)

    st.subheader("2. What the detector found")
    al = an.alerts
    k = st.columns(5)
    k[0].metric("Events", f"{st.session_state['n_events']:,}")
    k[1].metric("Users", f"{an.features['principal'].nunique():,}")
    k[2].metric("Days scored", len(an.scored_days))
    k[3].metric("Alerts raised", f"{len(al):,}")
    k[4].metric("Users alerted", f"{al['principal'].nunique():,}")

    g1, g2 = st.columns(2)
    with g1:
        st.markdown("**Alerts per day**")
        st.bar_chart(al.groupby("date").size().rename("alerts"))
    with g2:
        st.markdown("**Which behaviour family triggered the alert**")
        st.bar_chart(_family_chart(al))

    st.markdown("**Users with the most alerts**")
    top = (al.groupby("principal").agg(alerts=("rank", "size"), best_rank=("rank", "min"),
                                       max_score=("score", "max"), first_alert=("date", "min"))
           .sort_values(["alerts", "max_score"], ascending=False).head(15))
    st.dataframe(top, width="stretch")

    st.subheader("3. Daily triage queue")
    days = sorted(al["date"].unique())
    day = st.select_slider("Day", options=days, value=days[0], format_func=lambda d: str(d)[:10])
    today = al[al["date"] == day].sort_values("rank")
    st.caption(f"{len(today)} alert(s) on {str(day)[:10]} at a budget of {st.session_state['budget']} per day. "
               "p-values: how unusual each behaviour family is compared with this user's own past "
               "(smaller = more unusual).")
    for _, a in today.iterrows():
        with st.container(border=True):
            h1, h2 = st.columns([3, 2])
            h1.markdown(f"**#{int(a['rank'])}  {a['principal']}**  ·  score {a['score']:.2f}  ·  "
                        f"{FAMILY_SHORT.get(a['primary_family'], a['primary_family'])}")
            if a.get("rules_fired"):
                h2.caption("Signature rules also firing: " + a["rules_fired"].replace(",", ", "))
            st.code(a["explanation"], language=None)
            pv = pd.Series(a["family_pvalues"]).rename(index=lambda f: FAMILY_TEXT.get(f, f))
            st.dataframe(pv.rename("p-value").to_frame().T, hide_index=True)

    st.subheader("4. Download")
    out = al.drop(columns=["family_pvalues"]).assign(date=lambda d: d["date"].dt.strftime("%Y-%m-%d"))
    st.download_button("Alerts with explanations (CSV)", out.to_csv(index=False).encode(), "alerts.csv",
                       "text/csv")
    scores = pd.concat([s.assign(detector=n) for n, s in an.scores.items()])
    st.download_button("All detector scores (CSV)", scores.to_csv(index=False).encode(), "scores.csv", "text/csv")

    labels = st.session_state.get("labels")
    if labels is not None:
        st.subheader("5. Against the uploaded labels")
        ev = evaluate_upload(an, _model(), labels, st.session_state["budget"])
        ev["detector"] = ev["detector"].map(NAMES).fillna(ev["detector"])
        st.dataframe(ev.set_index("detector").round(3), width="stretch")
        st.caption("Precision = true alerts / alerts. Insiders caught = labelled users with at least one "
                   "alert on one of their malicious days. Only scored days count. Precision depends on how "
                   "many insiders the upload contains: the bundled sample is insider-rich, so its precision "
                   "is far higher than on a whole organisation (see Benchmark results).")


def page_results() -> None:
    summ = RESULTS / "campaign" / "summary.csv"
    hyp = RESULTS / "campaign" / "hypotheses.csv"
    if not summ.exists():
        st.info("No benchmark results yet: run `python scripts/run_campaign.py`.")
        return
    s = pd.read_csv(summ)
    st.markdown("**CERT r4.2 test windows, 10 alerts per day** (95% bootstrap CI over insiders / days)")
    t = s[(s["budget"] == 10) & s["metric"].isin(["dr_at_b", "precision_at_b"])].copy()
    t["value"] = t.apply(lambda r: f"{r['mean']:.3f} [{r['ci_lo']:.3f}, {r['ci_hi']:.3f}]", axis=1)
    st.dataframe(t.pivot(index="detector", columns="metric", values="value")
                 .rename(index=NAMES, columns={"dr_at_b": "Detection rate", "precision_at_b": "Precision"}),
                 width="stretch")
    if hyp.exists():
        h = pd.read_csv(hyp)
        st.markdown("**Hypotheses** (supported only if the whole 95% interval clears the threshold)")
        st.dataframe(h[["hypothesis", "metric", "threshold", "proposed_mean", "baseline_mean", "diff",
                        "ci_lo", "ci_hi", "verdict"]].round(3), hide_index=True, width="stretch")
    for fig in ("dr_vs_budget.png", "precision_vs_budget.png", "dr_by_scenario.png", "ablation.png"):
        if (FIGURES / fig).exists():
            st.image(str(FIGURES / fig))


def page_about() -> None:
    m = _model()
    st.markdown(f"""
**Model.** Trained on CERT r4.2 user-days from {m.trained_on[0]} to {m.trained_on[1]} ({m.n_users:,} users),
with settings tuned only on validation data. Users the model has never seen are compared with the
population instead of their own history.

**What happens to an upload.**
1. Each CSV is parsed exactly like the original dataset; free-text content is dropped.
2. Every user-day becomes 27 behaviour features in four families: *identity* (which PCs),
   *resource* (USB, executables, job and leak sites, external email, rare websites), *timing*
   (after hours, distance from the user's usual hours, weekends) and *volume*.
   "New" and "usual" only ever look at earlier days.
3. The proposed detector compares each user with their own past, turns each family's deviation
   into a calibrated p-value and fuses them; each day the **top-B** user-days become alerts.
4. Every alert names the family and the features that deviated, with today's value and the usual one.

**Caveat.** Features are computed from the uploaded period only, so upload a few weeks per user;
the first history days are not scored.
""")
    st.json(json.loads(json.dumps(m.settings, default=str)), expanded=False)


def main() -> None:
    st.title("Insider-Threat Analyst Console")
    st.caption("Budget-aware insider-threat detection with per-alert explanations · trained on the CMU CERT "
               "r4.2 benchmark (data © 2011 ExactData, LLC)")
    if not MODEL_PATH.exists():
        st.error("No trained model found. Run `python scripts/train_final_model.py` first.")
        return
    t1, t2, t3 = st.tabs(["Upload & detect", "Benchmark results", "How it works"])
    with t1:
        page_upload()
    with t2:
        page_results()
    with t3:
        page_about()


main()
