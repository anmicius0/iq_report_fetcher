# Sonatype Report Fetcher

[![Python 3.x](https://img.shields.io/badge/python-3.10-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/your-repo/your-project/releases/tag/v1.0.0)

This tool connects to your Sonatype IQ Server, fetches security scan reports for all your applications, and saves them as CSV files.

## 🚀 Getting Started

To get started, follow these steps:

1.  **Download the latest release.**

2.  **Configure settings:**

    Copy `config/.env.example` to `config/.env` and fill in your Sonatype IQ Server details.

    ```sh
    cp config/.env.example config/.env
    ```

    Refer to the [Configuration Reference](#-configuration-reference) for available options.

3.  **Run the tool:**

    ```sh
    ./iq-fetch
    ```

    On Windows: `iq-fetch.exe`

## 📝 Configuration Reference

Configure settings via `config/.env` (recommended) or environment variables.

**Example `.env` file:**

```
IQ_SERVER_URL=https://your-iq-server.com
IQ_USERNAME=your-username
IQ_PASSWORD=your-password
OUTPUT_DIR=raw_reports
NUM_WORKERS=8
LOG_LEVEL=INFO
```

## 🏗️ Project Structure

```
├── src/
│   └── iq_fetcher/
│       ├── __init__.py          # Package initialization
│       ├── config.py            # Configuration management
│       ├── client.py            # IQ Server API client
│       ├── fetcher.py           # Core report fetching logic
│       └── utils.py             # Utilities, logging, error handling
├── config/
│   ├── .env.example         # Configuration template
│   └── .env                 # Your configuration (not in git)
├── pyproject.toml           # Project dependencies (uv)
├── uv.lock                  # Locked dependencies
└── README.md
```
