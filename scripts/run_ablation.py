"""
run_ablation.py - being rewritten in Phase 7.

The previous version evaluated on a train == test split and a global top-B metric,
so its results were invalid. It is replaced by an ablation / sweep driver built on
the per-day budget evaluator (Phase 4) with >= 3 seeds and error bars.
"""
import sys

if __name__ == "__main__":
    sys.exit("run_ablation.py is pending Phase 7: the old implementation was removed because "
             "it evaluated on its own training data.")
