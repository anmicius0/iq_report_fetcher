"""Utility functions for Sonatype Report Fetcher: logging setup, path resolution, and error handling."""

# Standard library imports
import sys
import os
import logging
from typing import Callable, TypeVar, Any, Union, cast, Optional, List
from functools import wraps
from pathlib import Path
from dataclasses import dataclass

# Third-party imports
import requests
from dotenv import load_dotenv

typical_escape = "\x1b"


class Colors:
    """A simple container for terminal color codes."""

    GREEN = f"{typical_escape}[92m"
    RED = f"{typical_escape}[91m"
    BLUE = f"{typical_escape}[94m"
    YELLOW = f"{typical_escape}[93m"
    BOLD = f"{typical_escape}[1m"
    END = f"{typical_escape}[0m"


class PrettyFormatter(logging.Formatter):
    """A logging formatter that adds color and improves readability."""

    LOG_COLORS = {
        logging.DEBUG: Colors.BLUE,
        logging.INFO: Colors.GREEN,
        logging.WARNING: Colors.YELLOW,
        logging.ERROR: Colors.RED,
        logging.CRITICAL: Colors.RED + Colors.BOLD,
    }

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        color = self.LOG_COLORS.get(record.levelno, Colors.BLUE)
        return f"{color}{msg}{Colors.END}"


def setup_logging(log_dir: Path, log_level_str: str = "INFO") -> logging.Logger:
    logger = logging.getLogger("iq_fetcher")
    log_level = getattr(logging, log_level_str.upper(), logging.INFO)
    if not logger.handlers:
        logger.setLevel(log_level)
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(PrettyFormatter("%(message)s"))
        logger.addHandler(console_handler)
        log_dir.mkdir(parents=True, exist_ok=True)
        file_path = log_dir / "iq-fetch.log"
        file_handler = logging.FileHandler(file_path, encoding="utf-8")
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        )
        logger.addHandler(file_handler)
    return logger


logger = logging.getLogger("iq_fetcher")

# Helper functions for consistent logging formatting


def log_section(title: Optional[str] = None) -> None:
    """Log a section header."""
    logger.info("")
    if title:
        logger.info(title)


def log_start_header(title: str) -> None:
    """Log the start of a process or section."""
    logger.info(f"{title}")


def log_completion_summary(
    success_count: int, total_apps: int, failed_apps: Optional[List[str]] = None
) -> bool:
    """Log a summary of the completion status."""
    logger.info("🏁 Collection phase completed")
    logger.info(f"✅ Successfully processed: {success_count}/{total_apps} applications")
    if success_count == 0:
        logger.error("❌ No reports were successfully fetched")
        return False
    if failed_apps:
        logger.warning(f"⚠️  {len(failed_apps)} applications failed:")
        for app_name in failed_apps[:5]:
            logger.warning(f"   • {app_name}")
        if len(failed_apps) > 5:
            logger.warning(f"   • ... and {len(failed_apps) - 5} more")
    return True


def log_consolidation_result(output_path, row_count: int, file_size: int) -> None:
    """Log the result of the consolidation process."""
    logger.info("🎉 CONSOLIDATION COMPLETED SUCCESSFULLY")
    logger.info(f"💾 CSV file saved: {output_path}")
    logger.info(f"📊 Total rows generated: {row_count:,}")
    logger.info(f"📁 File size: {file_size:,} bytes")


F = TypeVar("F", bound=Callable[..., Any])
E = TypeVar("E", bound=BaseException)


def find_project_root(start_path: Union[str, Path]) -> Path:
    """Find and return the project root directory based on pyproject.toml or executable path."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    current = Path(start_path).resolve()
    for parent in current.parents:
        if (parent / "pyproject.toml").is_file():
            return parent
    return Path.cwd()


base_dir = find_project_root(__file__)


def resolve_path(path: Union[str, Path]) -> Path:
    """Resolve relative paths against the project root, or return absolute paths unchanged."""
    p = Path(path)
    if p.is_absolute():
        return p
    return base_dir / p


def handle_errors(func: F) -> F:
    """Decorator to handle errors for functions making requests or file operations."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except requests.RequestException as e:
            logger.error(f"API request failed: {e}")
            return None
        except (IOError, OSError) as e:
            logger.error(f"File operation failed: {e}")
            return False
        except Exception as e:
            logger.error(f"An unexpected error occurred: {e}", exc_info=True)
            sys.exit(1)

    return cast(F, wrapper)


dotenv_path = resolve_path(Path("config") / ".env")

# Load environment variables from .env if present
load_dotenv(dotenv_path)


@dataclass
class Config:
    """Simple configuration loaded from environment variables.

    Required:
    - IQ_SERVER_URL
    - IQ_USERNAME
    - IQ_PASSWORD
    Optional:
    - ORGANIZATION_ID
    - OUTPUT_DIR (default: raw_reports)
    - LOG_DIR (default: logs)
    - LOG_LEVEL (default: INFO)
    """

    iq_server_url: str = os.getenv("IQ_SERVER_URL", "")
    iq_username: str = os.getenv("IQ_USERNAME", "")
    iq_password: str = os.getenv("IQ_PASSWORD", "")
    organization_id: Optional[str] = os.getenv("ORGANIZATION_ID")
    output_dir: str = os.getenv("OUTPUT_DIR", "raw_reports")
    # Kept for backward compatibility; not used when running sequentially
    num_workers: int = int(os.getenv("NUM_WORKERS", str(os.cpu_count() or 1)))
    log_dir: str = os.getenv("LOG_DIR", "logs")
    log_level: str = os.getenv("LOG_LEVEL", "INFO")

    def __post_init__(self) -> None:
        if not self.iq_username.strip() or not self.iq_password.strip():
            raise ValueError("credentials must not be empty")
        if not self.iq_server_url.strip():
            raise ValueError("IQ_SERVER_URL must not be empty")
