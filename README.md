# yara_rule_tester

## Project Description
`yara_rule_tester` is a Python-based tool designed to scan HTTP headers stored in an SQLite database using YARA rules. It helps detect patterns and anomalies in proxy traffic by leveraging configurable YARA rulesets.

## Features
- Scans database entries using YARA rules.
- Supports multiple proxy configurations via YAML files.

## Prerequisites
- Python 3.6 or higher
- Required Python libraries: `yara-python`

## Installation
1. Clone the repository:
   ```bash
   git clone <repository_url>
   cd yara_rule_tester
   ```
2. Install dependencies:
   ```bash
   pip install yara-python
   ```

## Usage
1. Scan the database using YARA rules:
   ```bash
   python yara_rule_tester.py <sqlite_db_file> <config_file> [verbose]
   ```
   Example:
   ```bash
   python yara_rule_tester.py data.db all.yaml verbose
   ```

## Configuration
- YAML configuration files define proxies, their IPs, and associated YARA rulesets.
- Example (`all.yaml`):
  ```yaml
  proxies:
    - ip: "146.190.17.33"
      proxy: "tinyproxy"
      yara_ruleset: "./rules/tinyproxy.yar"
    - ip: "159.65.95.40"
      proxy: "modlishka"
      yara_ruleset: "./rules/modlishka.yar"
  ```

## Directory Structure
- `rules/`: Contains YARA rulesets for different proxies.
- `*.yaml`: Configuration files for proxies and rulesets.
- `yara_rule_tester.py`: Main script to scan the database using YARA rules.
