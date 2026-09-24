"""
cti.util.seeds
--------------
One place to seed every random source the project touches.
Every CLI entrypoint calls set_all_seeds(cfg["random_seed"]) before anything
else so that all experiments are deterministic.
"""
from __future__ import annotations

import random

import numpy as np


def set_all_seeds(seed: int) -> None:
    """Seed Python random, NumPy, and configure sklearn global defaults.

    Parameters
    ----------
    seed:
        Integer seed value (typically read from ``cfg["random_seed"]``).
    """
    random.seed(seed)
    np.random.seed(seed)

    # sklearn uses numpy's global RNG but also accepts ``random_state`` per
    # estimator.  We expose a helper so callers can grab a seeded RNG object.
    _configure_sklearn_global(seed)


def make_rng(seed: int) -> np.random.Generator:
    """Return a new, seeded ``numpy.random.Generator`` for local use."""
    return np.random.default_rng(seed)


def _configure_sklearn_global(seed: int) -> None:
    """Patch sklearn's global check_random_state to use our seed.

    sklearn does not have a single global seed knob; we enforce determinism by
    always passing ``random_state=seed`` explicitly in every estimator
    constructor.  This function exists as a reminder and future hook.
    """
    # No public API in sklearn for a global RNG seed — determinism is
    # achieved by explicit ``random_state=`` arguments in each estimator.
    _ = seed  # intentionally unused; determinism via explicit args
