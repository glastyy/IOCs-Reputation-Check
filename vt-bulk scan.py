import pandas as pd
import requests
from tqdm import tqdm
from datetime import datetime
import itertools

# Constants
API_KEYS = ['YOUR_API_KEY_1', 'YOUR_API_KEY_2']  # Add more API keys as needed
VT_URLS = {
    'file': 'https://www.virustotal.com/api/v3/files/',
    'domain': 'https://www.virustotal.com/api/v3/domains/',
    'ip': 'https://www.virustotal.com/api/v3/ip_addresses/',
    'url': 'https://www.virustotal.com/api/v3/urls/'
}

# Function to get VT report
def get_vt_report(ioc, ioc_type, api_key):
    headers = {
        "x-apikey": api_key
    }
    url = VT_URLS[ioc_type] + ioc
    response = requests.get(url, headers=headers)
    print(f"Requesting {url} with API key {api_key[:5]}...")  # Debug statement
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error {response.status_code}: {response.text}")  # Debug statement
        return None

# Determine IOC type
def determine_ioc_type(ioc):
    if ioc.count('.') == 3 and all(part.isdigit() and 0 <= int(part) < 256 for part in ioc.split('.')):
        return 'ip'
    elif '.' in ioc and '/' not in ioc:
        return 'domain'
    elif '/' in ioc:
        return 'url'
    else:
        return 'file'

# Function to check Crowdstrike detection
def check_crowdstrike_detection(scans):
    if 'CrowdStrike Falcon' in scans and scans['CrowdStrike Falcon']['category'] == 'malicious':
        return 'Yes'
    else:
        return 'No'

# Function to check SentinelOne detection
def check_sentinelone_detection(scans):
    if 'SentinelOne' in scans and scans['SentinelOne']['category'] == 'malicious':
        return 'Yes'
    else:
        return 'No'

# Read input Excel file
input_file = 'input.xlsx'
try:
    df = pd.read_excel(input_file)
except FileNotFoundError:
    print(f"Error: The file {input_file} does not exist.")
    exit()

# Create a list to store output data
output_data = []

# Create an iterator for the API keys, cycling through them
api_key_cycle = itertools.cycle(API_KEYS)

# Process each cell in the DataFrame
ioc_counter = 0
for column in df.columns:
    for cell in df[column]:
        if isinstance(cell, str):
            ioc = cell.strip()
            ioc_type = determine_ioc_type(ioc)

            # Get the current API key, switching every 4 IOCs
            if ioc_counter % 4 == 0:
                current_api_key = next(api_key_cycle)
            ioc_counter += 1

            # Get VT report
            report = get_vt_report(ioc, ioc_type, current_api_key)

            if report:
                if ioc_type == 'file':
                    md5 = report['data']['attributes']['md5']
                    sha1 = report['data']['attributes']['sha1']
                    sha256 = report['data']['attributes']['sha256']
                else:
                    md5 = sha1 = sha256 = None

                score = report['data']['attributes']['last_analysis_stats']['malicious']

                # Check for Microsoft detection
                microsoft_detection = 'No'
                scans = report['data']['attributes'].get('last_analysis_results', {})
                if 'Microsoft' in scans and scans['Microsoft']['category'] == 'malicious':
                    microsoft_detection = 'Yes'

                # Check for Crowdstrike detection
                crowdstrike_detection = check_crowdstrike_detection(scans)

                # Check for SentinelOne detection
                sentinelone_detection = check_sentinelone_detection(scans)

                output_data.append({
                    'Input': ioc,
                    'MD5': md5,
                    'SHA1': sha1,
                    'SHA256': sha256,
                    'Score': score,
                    'Microsoft Detection': microsoft_detection,
                    'Crowdstrike Detection': crowdstrike_detection,
                    'SentinelOne Detection': sentinelone_detection
                })
            else:
                output_data.append({
                    'Input': ioc,
                    'MD5': None,
                    'SHA1': None,
                    'SHA256': None,
                    'Score': 'Not found',
                    'Microsoft Detection': 'Not found',
                    'Crowdstrike Detection': 'Not found',
                    'SentinelOne Detection': 'Not found'
                })

# Convert output data to DataFrame
output_df = pd.DataFrame(output_data)

# Generate output file name with current date and timestamp
current_datetime = datetime.now().strftime("%Y%m%d_%H%M%S")
output_file = f"output_{current_datetime}.xlsx"

# Write output to Excel
output_df.to_excel(output_file, index=False)

print(f"Reputation check completed and saved to {output_file}")
