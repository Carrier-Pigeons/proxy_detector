import yara
import sqlite3
import sys
import yaml
import re

verbose = False
list_flag = None
specific_proxy = None

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
    rule_names = []
    if yara_rules_paths != None:
        for yara_rule_path in yara_rules_paths:
            print(f"Loading YARA rule from: {yara_rule_path}")
            try:
                rule = yara.compile(filepath=yara_rule_path)
                rules.append(rule)
                with open(yara_rule_path, "r") as file:
                    rule_text = file.read()
                    rule_names.append(re.findall(r"rule\s+(\w+)", rule_text))
            except yara.SyntaxError as e:
                print(f"YARA syntax error: {e}")
                sys.exit(1)
            except yara.Error as e:
                print(f"YARA error: {e}")
                sys.exit(1)
    return rules, rule_names

def scan_text(rules, names, text):
    """Scans the given text using YARA rules."""
    matches = []
    fails = []
    for rule in rules:
        curr_match = rule.match(data=text)
        if len(curr_match) != 0:
            matches.append([str(match) for match in curr_match])
    for name in names:
        if name not in matches:
            fails.append(name)
    return matches, fails 

def print_list(flag, id_text, headers_text, proxy_detected):
    if list_flag == flag:
        print(f"{flag} on id: {id_text}: Detected as {proxy_detected}\n{headers_text}\n")

def calculate_metrics(tp, fp, tn, fn):
    """Calculates precision, recall, and F1 score."""
    if tp + fp > 0:
        precision = tp / (tp + fp)
    else:
        precision = 0.0

    if tp + fn > 0:
        recall = tp / (tp + fn)
    else:
        recall = 0.0

    if precision + recall > 0:
        f1_score = 2 * (precision * recall) / (precision + recall)
    else:
        f1_score = 0.0

    return precision, recall, f1_score

def scan_sqlite_database(db_path, config_file):
    table_name = "ssl_logs"
    id_column_name = "id"
    ip_column_name = "ip"
    headers_column_name = "headers"
    ips, proxies, rulesets = parse_config(config_file)

    overall_total = 0
    overall_tp = 0
    overall_fp = 0
    overall_tn = 0
    overall_fn = 0
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute(f"SELECT rowid, {id_column_name}, {headers_column_name}, {ip_column_name} FROM {table_name}")
        rows = cursor.fetchall()

        for i, ruleset_paths in enumerate(rulesets, start=0):
            if specific_proxy and proxies[i].lower() != specific_proxy.lower():
                continue

            print(f"\n========== Parsing Ruleset {proxies[i]} ==========\n")
            rules, names = load_yara_rules(ruleset_paths['rules'])
            total = 0
            total_from_proxy = 0
            total_not_from_proxy = 0
            fail = 0
            fail_from_proxy = 0
            fail_not_from_proxy = 0
            for rowid, id_text, headers_text, ip_text in rows:
                if headers_text:
                    matches, fails = scan_text(rules, names, headers_text)
                    is_from_proxy = (ip_text == ips[i])
                    if len(matches) == len(names):
                        if not is_from_proxy:
                            fail += 1
                            fail_not_from_proxy += 1
                            total_not_from_proxy += 1
                            if verbose:
                                print(f"Failure on id: {id_text}: Detected as {proxies[i]} but request was not from proxy\n{headers_text}\n")
                            print_list("FP", id_text, headers_text, proxies[i])
                        else: 
                            total_from_proxy += 1
                            if verbose:
                                print(f"Success on id: {id_text}: Detected as {proxies[i]}\n{headers_text}\n")
                            print_list("TP", id_text, headers_text, proxies[i])
                    else:
                        if is_from_proxy:
                            fail += 1
                            fail_from_proxy += 1
                            total_from_proxy += 1
                            if verbose:
                                print(f"Failure on id: {id_text}: Detected as {proxies[i]} but request was from proxy\n{headers_text}\n")
                            print_list("FN", id_text, headers_text, proxies[i])
                        else:
                            total_not_from_proxy += 1
                            print_list("TN", id_text, headers_text, proxies[i])
                total += 1
                
            if (total_from_proxy == 0):
                total_from_proxy = -.01 # Handle division by 0
            
            TP = total_from_proxy - fail_from_proxy
            FP = fail_not_from_proxy
            TN = total_not_from_proxy - fail_not_from_proxy
            FN = fail_from_proxy

            overall_total += total
            overall_tp += TP
            overall_fp += FP
            overall_tn += TN
            overall_fn += FN
                                    
            precision, recall, f1_score = calculate_metrics(TP, FP, TN, FN)
            
            print("")
            print(f"Total Requests Parsed for {proxies[i]}: {total}")
            print(f"Total Requests from {proxies[i]}: {total_from_proxy}")
            print("")
            print("Confusion Matrix:")
            print(f"True Positive (TP): {TP} | {100 * TP/total:.3f}% of total | {100 * TP/total_from_proxy:.3f}% of true value")
            print(f"False Positive (FP): {FP} | {100 * FP/total:.3f}% of total")
            print(f"True Negative (TN): {TN} | {100 * TN/total:.3f}% of total | {100 * TN/(total-total_from_proxy):.3f}% of true value")
            print(f"False Negative (FN): {FN} | {100 * FN/total:.3f}% of total")
            print("")
            print(f"Precision: {precision:.3f}")
            print(f"Recall: {recall:.3f}")
            print(f"F1 Score: {f1_score:.3f}")
            print("")
        
        if not specific_proxy:
            precision, recall, f1_score = calculate_metrics(overall_tp, overall_fp, overall_tn, overall_fn)
            print(f"\n========== Overall Statistics ==========")
            print("")
            print(f"Total Requests Parsed: {overall_total}")
            print("")
            print("Confusion Matrix:")
            print(f"True Positive (TP): {overall_tp} | {100 * overall_tp/overall_total:.3f}% of total")
            print(f"False Positive (FP): {overall_fp}")
            print(f"True Negative (TN): {overall_tn} | {100 * overall_tn/overall_total:.3f}% of total")
            print(f"False Negative (FN): {overall_fn}")
            print("")
            print(f"Precision: {precision:.3f}")
            print(f"Recall: {recall:.3f}")
            print(f"F1 Score: {f1_score:.3f}")
            print("")
            
        conn.close()
    except sqlite3.Error as e:
        print(f"SQLite error: {e}")
        sys.exit(1)

if len(sys.argv) < 3:
    print("Usage: python yara_rule_tester.py <sqlite_db_file> <config_file> [-v] [flag=<tp|fp|tn|fn>] [proxy=<proxy_name>]")
    sys.exit(1)

sqlite_db_file = sys.argv[1]
config_file = sys.argv[2]
for arg in sys.argv[3:]:
    if arg == "-v":
        print("setting verbose")
        verbose = True
    elif arg.startswith("flag="):
        list_flag = arg.split("=")[1].upper()
    elif arg.startswith("proxy="):
        specific_proxy = arg.split("=")[1]

scan_sqlite_database(sqlite_db_file, config_file)