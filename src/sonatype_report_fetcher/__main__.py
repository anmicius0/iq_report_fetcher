#!/usr/bin/env python3
"""Entry point for Sonatype IQ Server Raw Report Fetcher CLI.

Fetches and processes raw scan reports from Sonatype IQ Server.
"""

from sonatype_report_fetcher.utils import (
    Config,
    resolve_path,
    handle_errors,
    setup_logging,
    logger,
    log_start_header,
)
from sonatype_report_fetcher.fetcher import RawReportFetcher


@handle_errors
def fetch() -> None:
    """Start the raw report fetch process and manage configuration and logging setup."""
    # Load configuration first, then configure logging before emitting logs
    cfg = Config()  # type: ignore
    log_dir = resolve_path(cfg.log_dir)
    setup_logging(log_dir, cfg.log_level)

    # Now that logging is configured, emit startup messages
    log_start_header("IQ SERVER REPORT FETCHER STARTING")
    logger.info("🔧 Loading configuration…")
    logger.info("✅ Configuration loaded successfully")
    logger.info("🔧 Configuring logger…")
    logger.info(f"✅ Log directory: {log_dir}")
    logger.info("")
    RawReportFetcher(cfg).fetch_all_reports()


if __name__ == "__main__":
    fetch()
