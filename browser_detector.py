import sqlite3
import re
import sys
from collections import Counter

# A rudimentary set of regex patterns to detect browser families

browser_patterns = [
    ('Edge', re.compile(r'Edg/|Edge/')),
    ('Opera', re.compile(r'OPR/|Opera/')),
    ('YaBrowser', re.compile(r'YaBrowser/')),
    ('Whale', re.compile(r'Whale/')),
    ('Chrome', re.compile(r'Chrome/')),
    ('Firefox', re.compile(r'Firefox/')),
    ('Safari', re.compile(r'Safari/')),
    ('curl', re.compile(r'curl/')),
    ('Postman', re.compile(r'PostmanRuntime/')),
    ('Bot', re.compile(r'bot|spider|crawl', re.IGNORECASE)),
    ('Other', re.compile(r'.*')),  # fallback
]

def detect_browser_family(ua):
    for name, pat in browser_patterns:
        if pat.search(ua):
            return name
    return 'Other'

def extract_user_agents_with_count(db_path, table_name="ssl_logs", headers_column="headers"):
    user_agent_counts = Counter()
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(f"SELECT {headers_column} FROM {table_name}")
    rows = cursor.fetchall()
    ua_regex = re.compile(r"User-Agent:\s*(.+)", re.IGNORECASE)
    for (headers,) in rows:
        if not headers:
            continue
        for line in headers.splitlines():
            m = ua_regex.match(line.strip())
            if m:
                user_agent = m.group(1).strip()
                user_agent_counts[user_agent] += 1
    conn.close()
    return user_agent_counts

def summarize_browsers(user_agent_counts):
    summary = Counter()
    for ua, count in user_agent_counts.items():
        browser = detect_browser_family(ua)
        summary[browser] += count
    return summary

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python browser_detector.py <sqlite_db_file>")
        sys.exit(1)
    db_file = sys.argv[1]
    user_agent_counts = extract_user_agents_with_count(db_file)
    summary = summarize_browsers(user_agent_counts)
    print("Browser summary:")
    for browser, count in summary.most_common():
        print(f"{browser:10}: {count}")