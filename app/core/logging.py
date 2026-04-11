from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path

from app.core.config import Settings


def setup_audit_logger(settings: Settings) -> logging.Logger:
    logger = logging.getLogger("secure_auth.audit")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    if os.getenv("VERCEL"):
        handler = logging.StreamHandler()
    else:
        log_path = Path(settings.audit_log_path)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(log_path, maxBytes=1_048_576, backupCount=5, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(handler)
    logger.propagate = False
    return logger
