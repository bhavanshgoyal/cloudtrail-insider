"""
cti.features.pipeline
---------------------
Feature-family definitions and vectorised helpers shared by the feature builder
(``cti.features.cert``) and the detectors.

Four feature families, each capturing a different aspect of deviation (objective O1):

=========  ==========================  =======================================
family     prefixes                    what it captures
=========  ==========================  =======================================
identity   ``idn_`` ``err_``           *who / where*: which machines are used
resource   ``res_`` ``rar_``           *what*: removable media, sensitive sites,
                                       external email, rarely-seen resources
temporal   ``tmp_``                    *when*: after hours, away from the
                                       user's own usual hours, weekends
volume     ``vol_`` ``div_``           *how much / how varied*
=========  ==========================  =======================================
"""
from __future__ import annotations

import numpy as np
import pandas as pd

# Single source of truth for detector feature families.
FAMILY_PREFIXES: dict[str, tuple[str, ...]] = {
    "identity": ("idn_", "err_"),
    "resource": ("res_", "rar_"),
    "temporal": ("tmp_",),
    "volume":   ("vol_", "div_"),
}


def family_columns(columns, family: str) -> list[str]:
    """Feature columns of ``columns`` that belong to ``family``."""
    prefixes = FAMILY_PREFIXES[family]
    return [c for c in columns if c.startswith(prefixes)]


def feature_columns(df: pd.DataFrame) -> list[str]:
    """Names of feature columns (everything except principal and date)."""
    return [c for c in df.columns if c not in {"principal", "date"}]


def _novelty(pid: np.ndarray, x: np.ndarray, day: np.ndarray, D: int, ukey: np.ndarray,
             g: np.ndarray, G: int) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Causal novelty of attribute ``x`` per principal.

    Returns ``(new_events, new_values, new_mask)``: per group, the number of
    events whose (principal, x) pair was first seen that very day, the number
    of distinct such pairs, and the per-event boolean.
    """
    if len(x) == 0:
        return np.zeros(G), np.zeros(G), np.zeros(0, dtype=bool)
    M = int(x.max()) + 1
    pair = pid * M + x
    up, inv = np.unique(pair, return_inverse=True)
    first = pd.Series(day).groupby(inv).min().to_numpy()
    new_mask = day == first[inv]
    new_events = np.bincount(g, weights=new_mask, minlength=G)
    gi = np.searchsorted(ukey, (up // M) * D + first)
    new_values = np.bincount(gi, minlength=G).astype(float)
    return new_events, new_values, new_mask


def _nunique(g: np.ndarray, x: np.ndarray, G: int) -> np.ndarray:
    if len(x) == 0:
        return np.zeros(G)
    M = int(x.max()) + 1
    up = np.unique(g.astype(np.int64) * M + x)
    return np.bincount(up // M, minlength=G).astype(float)
