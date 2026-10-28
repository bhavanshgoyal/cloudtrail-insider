"""
train_final_model.py
--------------------
Fit every detector on the last rolling origin's train + val window (frozen settings) and save
models/cert_model.pkl for the frontend. Nothing after that window is used, so the test window
(and the sample upload cut from it) stays unseen.

    python scripts/train_final_model.py
"""
import logging

from cti.experiment import apply_frozen_configs
from cti.inference import train_final_model
from cti.util.config import load_config

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
train_final_model(apply_frozen_configs(load_config()))
