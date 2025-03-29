import yara
import sqlite3
import sys
import yaml

verbose = False
display = False

def parse_config(config_file):
    with open(config_file, "r") as file:
        config = yaml.safe_load(file)
    proxy_entries = config['proxies']
    ips = []
    proxies = []
    rules = []
    for proxy in proxy_entries:
        ips.append(proxy['ip'])
        proxies.append(proxy['proxy'])
        rules.append(proxy['yara_ruleset'])
    return ips, proxies, rules

def load_yara_rules(yara_rules_paths):
    """Compiles YARA rules from a list of files."""
    rules = []
    for yara_rule_path in yara_rules_paths:
        print(f"Loading YARA rule from: {yara_rule_path}")
        try:
            rule = yara.compile(filepath=yara_rule_path)
            rules.append(rule)
        except yara.SyntaxError as e:
            print(f"YARA syntax error: {e}")
            sys.exit(1)
        except yara.Error as e:
            print(f"YARA error: {e}")
            sys.exit(1)
    return rules

def scan_text(rules, text):
    """Scans the given text using YARA rules."""
    matches = []
    for rule in rules:
        matches.extend(rule.match(data=text))
    return matches


def scan_sqlite_database(db_path, config_file):
    table_name = "ssl_logs"
    id_column_name = "id"
    ip_column_name = "ip"
    headers_column_name = "headers"
    ips, proxies, yara_rules_paths = parse_config(config_file)
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute(f"SELECT rowid, {id_column_name}, {headers_column_name}, {ip_column_name} FROM {table_name}")
        rows = cursor.fetchall()
        
        for i, ruleset_paths in enumerate(yara_rules_paths, start=0):
            print(f"Parsing Ruleset {proxies[i]}")
            rules = load_yara_rules(ruleset_paths)
            total = 0
            total_from_proxy = 0
            total_not_from_proxy = 0
            fail = 0
            fail_from_proxy = 0
            fail_not_from_proxy = 0
            for rowid, id_text, headers_text, ip_text in rows:
                if headers_text:
                    matches = scan_text(rules, headers_text)
                    if matches:
                        if ip_text != ips[i]:
                            fail += 1
                            fail_not_from_proxy += 1
                            total_not_from_proxy += 1
                            if verbose:
                                print(f"Failure on id: {id_text}: Request was not from proxy")
                            if display:
                                print(f"-------------------------------------")
                                print(f"Rule triggered on id: {id_text}: Request Headers: {headers_text}")
                        else: 
                            total_from_proxy += 1
                    else:
                        if ip_text == ips[i]:
                            fail += 1
                            fail_from_proxy += 1
                            total_from_proxy += 1

                            if verbose:
                                print(f"Failure on id: {id_text}: Request was from proxy")
                            if display:
                                print(f"-------------------------------------")
                                print(f"Rule triggered on id: {id_text}: Request Headers: {headers_text}")

                        else:
                            total_not_from_proxy += 1
                total += 1
            percent = 100 * (total - fail)/total
            percent_from_proxy = 0
            if (total_from_proxy != 0):
                percent_from_proxy = 100 * (total_from_proxy - fail_from_proxy)/total_from_proxy
            precent_not_from_proxy = 0
            if (total_not_from_proxy != 0):
                precent_not_from_proxy = 100 * (total_not_from_proxy - fail_not_from_proxy)/total_not_from_proxy
            print(f"-------------------------------------")
            print(f"Summary {proxies[i]}: {total - fail}/{total} | {percent:.2f}%" )
            print(f"Total from proxy: {total_from_proxy} | Total not from proxy: {total_not_from_proxy}")
            print(f"Summary from proxy: {total_from_proxy - fail_from_proxy}/{total_from_proxy} | {percent_from_proxy:.2f}%" )
            print(f"Summary not from proxy: {total_not_from_proxy - fail_not_from_proxy}/{total_not_from_proxy} | {precent_not_from_proxy:.2f}%" )
            print("\n")

            
        conn.close()
    except sqlite3.Error as e:
        print(f"SQLite error: {e}")
        sys.exit(1)
        
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python yara_rule_tester.py <sqlite_db_file> <config_file> <optional_verbose>")
        sys.exit(1)
    
    sqlite_db_file = sys.argv[1]
    config_file = sys.argv[2]
    if len(sys.argv) >= 4 and (sys.argv[3] or sys.argv[4])  == "verbose":
        print("setting verbose")
        verbose = True
    if len(sys.argv) >= 4 and (sys.argv[3] or sys.argv[4]) == "display":
        print("setting display")
        display = True
    
    scan_sqlite_database(sqlite_db_file, config_file)

