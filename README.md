# IOC Reputation Checker

## About

The **IOC Reputation Checker** is a Python script designed to automate the process of checking the reputation of various Indicators of Compromise (IOCs) such as files, domains, IP addresses, and URLs. The script leverages VirusTotal and AbuseIPDB APIs to gather reputation data, which can be invaluable for cybersecurity professionals during threat hunting, incident response.

## Features

- **Multi-Source Reputation Check**: Queries both VirusTotal and AbuseIPDB for comprehensive reputation data.
- **Multiple API Key Support**: Supports multiple API keys for both VirusTotal and AbuseIPDB, allowing for extended usage without hitting daily limits.
- **Threading**: Utilizes multi-threading to handle large volumes of IOCs efficiently.
- **Excel Integration**: Reads IOCs from an input Excel file and writes the results to an output Excel file, making it easy to integrate into existing workflows.
- **Detailed Output**: Provides detailed output, including hash values, detection status from popular security vendors, and reputation scores from AbuseIPDB.

## How to Use

### Prerequisites

- Python 3.x
- Required Python packages: `pandas`, `requests`, `tqdm`, `openpyxl`

Install the required packages using pip:

```bash
pip install pandas requests tqdm openpyxl
```

### Script Overview

1. **Input File**: The script reads IOCs from an input Excel file named `input.xlsx`. The IOCs can be files, domains, IP addresses, or URLs.
2. **Reputation Check**: For each IOC, the script queries VirusTotal and AbuseIPDB (for IPs only) to gather reputation data.
3. **Output File**: The script writes the results to an Excel file, including details such as hash values, detection statuses, and reputation scores.

### Example Usage

Run the script with the desired number of threads:

```bash
python ioc_reputation_checker.py --threads 10
```

### Notes

- **API Limits**: The script is configured to handle API key limits by cycling through multiple keys. Ensure that your API keys have enough daily quota to handle the number of IOCs you intend to process.
- **Input File Format**: Ensure that the input file is an Excel file (`.xlsx`) and that the IOCs are correctly formatted (e.g., valid IP addresses, domain names, etc.).
- **Output File Naming**: The output file is named with the current date and time to avoid overwriting previous results.
