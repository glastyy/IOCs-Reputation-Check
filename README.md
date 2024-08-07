### About

The `VirusTotal IOC Checker` is a Python script designed to automate the process of checking the reputation of various Indicators of Compromise (IOCs) such as files, domains, IP addresses, and URLs using the VirusTotal API. This script reads IOCs from an input Excel file, queries VirusTotal for reputation information, processes the responses, and writes the results to an output Excel file. It supports multi-threading to improve performance by allowing multiple IOCs to be processed simultaneously.

### Features

- **Multi-threaded Processing**: Utilizes multiple threads to perform API requests in parallel.
- **Support for Multiple IOC Types**: Handles files, domains, IP addresses, and URLs.
- **Detection Checks**: Checks for detections by Microsoft, CrowdStrike Falcon, and SentinelOne.
- **Rate Limiting**: Manages API key rotation to stay within VirusTotal's rate limits.

### How to Use

1. **Install Dependencies**: Ensure you have the required libraries installed. You can install them using pip:
    ```bash
    pip install pandas requests tqdm openpyxl
    ```

2. **Prepare Input File**: Create an Excel file named `input.xlsx` with the IOCs listed in a column. Ensure the file is in the same directory as the script.

3. **Run the Script**:
    - Open a terminal or command prompt.
    - Navigate to the directory containing the script.
    - Run the script using the following command:
      ```bash
      python vt_ioc_checker.py --threads <num_threads>
      ```
      Replace `<num_threads>` with the desired number of threads (e.g., 4).

4. **Output**: The script will process the IOCs and generate an output Excel file with the results. The file name will include the current date and timestamp (e.g., `output_20240101_123456.xlsx`).

### Script Overview

- **API_KEYS**: List of VirusTotal API keys. Add more keys as needed to distribute the load.
- **VT_URLS**: Dictionary of API endpoints for different IOC types.
- **MAX_REQUESTS_PER_MINUTE**: Set the maximum number of requests per minute based on your API key limits.
- **get_vt_report**: Function to get the VirusTotal report for a given IOC.
- **determine_ioc_type**: Function to determine the type of IOC (file, domain, IP, or URL).
- **check_crowdstrike_detection**: Function to check for CrowdStrike Falcon detection.
- **check_sentinelone_detection**: Function to check for SentinelOne detection.
- **clean_and_validate_ioc**: Function to clean and validate the IOC.
- **process_ioc**: Function to process a single IOC and return the results.
- **main**: Main function to read the input file, process the IOCs using multiple threads, and write the results to an output file.

### Example Usage

```bash
python vt_ioc_checker.py --threads 4
```

This command will run the script using 4 threads, processing the IOCs listed in `input.xlsx` and saving the results to an output file with a timestamped name.

### Notes

- Ensure that the number of threads does not exceed the combined rate limit of the provided API keys.
- The script includes basic validation for IOCs and handles different types of IOCs appropriately.
- Output results include details such as MD5, SHA1, SHA256, detection scores, and specific detections by Microsoft, CrowdStrike Falcon, and SentinelOne.

This script provides a robust and efficient way to check the reputation of IOCs using VirusTotal, helping in the quick identification of potential threats.
