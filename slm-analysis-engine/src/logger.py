"""Simple logger for analysis engine."""
import logging
import sys

# Create logger
LOGGER = logging.getLogger("analysis_engine")
LOGGER.setLevel(logging.INFO)

# Create console handler if not already configured
if not LOGGER.handlers:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    )
    LOGGER.addHandler(handler)

