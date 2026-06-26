import logging
import logging.config
from pathlib import Path

from app.core.config import settings


def setup_logging() -> None:
    """Configure centralized console and file logging for the application."""

    log_level = getattr(logging, settings.log_level.upper(), logging.INFO)
    log_dir = Path(__file__).resolve().parents[2] / "logs"
    log_dir.mkdir(exist_ok=True)

    logging.config.dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "default": {
                    "format": "%(asctime)s %(levelname)s [%(name)s] %(message)s",
                    "datefmt": "%Y-%m-%d %H:%M:%S",
                }
            },
            "handlers": {
                "console": {
                    "class": "logging.StreamHandler",
                    "level": log_level,
                    "formatter": "default",
                    "stream": "ext://sys.stdout",
                },
                "file": {
                    "class": "logging.handlers.RotatingFileHandler",
                    "level": log_level,
                    "formatter": "default",
                    "filename": str(log_dir / "threatlens.log"),
                    "maxBytes": 5_242_880,
                    "backupCount": 5,
                },
            },
            "root": {"handlers": ["console", "file"], "level": log_level},
        }
    )


logger = logging.getLogger("threatlens")
