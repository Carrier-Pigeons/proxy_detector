# proxy_detector

## Project Description
`proxy_detector` is a Python-based tool designed to scan HTTP headers stored in an SQLite database using YARA rules. It helps detect patterns and anomalies in proxy traffic by leveraging configurable YARA rulesets.

## Features
- Scans database entries using YARA rules.
- Supports multiple proxy configurations via YAML configuration.

## Prerequisites
- Python 3.6 or higher
- Required Python libraries: `yara-python`

## Installation
1. Clone the repository:
   ```bash
   git clone <repository_url>
   cd proxy_detector
   ```
2. Install dependencies:
   ```bash
   pip install yara-python
   ```

## Usage
Scan the database using YARA rules. With just the required flags, the program will run all the proxies in `proxies.yaml` and print out information on what gets flagged:
   ```bash
   python proxy_detector.py <sqlite_db_file> <config_file>
   ```
   Example:
   ```bash
   python proxy_detector.py data.db all.yaml
   ```

Optional flags can be added in any order to print out verbose mode, specify a proxy to display, and to print the requests that are being triggered as true/false positive/negative respectively. Leaving out any of these optional flags will run it against all the proxies in `proxies.yaml` or not print detailed information about the true/false positive/negative results:
   ```bash
   python proxy_detector.py <sqlite_db_file> <config_file> <-v> <flag=[tp][fp][tn][fn]> <proxy=[proxy_name]>
   ```
   Example:
   ```bash
   python proxy_detector.py data.db all.yaml flag=fn proxy=modlishka
   ```

## Configuration
- YAML configuration files define proxies, their IPs, and associated YARA rulesets. The IP address identifies what proxy in the environment the request passed through in order to facilitate true request origin for testing and analysis accuracy.
- Example (`proxies.yaml`):
  ```yaml
  proxies:
    - proxy: "proxy1"
      ip: "ip.of.proxy.1"
      yara_ruleset:
        rules:
          - "./rules/rule1.yar"
          - "./rules/rule2.yar"
    - proxy: "proxy2"
    ip: "ip.of.proxy.2"  
    yara_ruleset:
      rules:
        - "./rules/rule2.yar"
  ```

## Directory Structure
- `rules/`: Contains YARA rulesets for different proxies.
- `*.yaml`: Configuration files for proxies and rulesets.
- `proxy_detector.py`: Main script to scan the database using YARA rules.

## Analysis
- Precision identifies the accuracy of positive predictions
  - "Of all the items labeled as positive, how many were actually positive?"
- Recall measures the ability to find all positive instances
  - "Of all the actual positives, how many did we correctly identify?"
- F1 Score provides a balance of both precision and recall
  - F1 Score = 2 * (Precision * Recall) / (Precision + Recall)