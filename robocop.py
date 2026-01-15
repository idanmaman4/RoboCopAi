from collections import defaultdict, Counter
import mysql.connector
import numpy as np
import robocop
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
import json
from collections import defaultdict,deque

DB_HOST = "10.58.22.31"
DB_PORT = 3306
DB_USER = "root"
DB_PASSWORD = "root"
DB_NAME = "syscallsdb"

TABLE_NAME = "syscall"


WINDOW_SIZE = 4
FETCH_LIMIT = 3000000
MAX_TRAIN_WINDOWS = 1300000

NORMAL_TEST_LIMIT = 1000000   # how many rows to fetch for normal evaluation
VIRUS_TEST_LIMIT  = 1000000   # how many rows to fetch for virus evaluation

# OCSVM
NU = 0.01
GAMMA = 0.01

# Severity thresholds on decision_function score (more negative => more anomalous)
HIGH_THR = -0.4
MEDIUM_THR = -0.2

# Alert rule: count only HIGH anomalies that are NOT monotonic (unique_syscalls > 1)
ALERT_HIGH_NON_MONO_THRESHOLD = 10

# Print how many anomaly examples to show
PRINT_EXAMPLES_PER_BUCKET = 10

with open("nt-per-system.json") as file:
    syscalls_names= json.load(file)

table = {syscall_num:syscall_name for syscall_name,syscall_num in  syscalls_names["Windows 10"]["22H2"].items()}

def convert_syscall_num_to_string(num : int): 
    return table.get(num,"UNKOWN")


def build_pid_windows(events):
    pid_cache = defaultdict(list)
    windows = []

    for e in events:
        pid = e["pid"]
        buf = pid_cache[pid]

        buf.append(e)

        if len(buf) == WINDOW_SIZE:
            windows.append(list(buf))
            buf.clear()

    return windows


def fetch_events(where_clause: str , limit = None):
    conn = mysql.connector.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME
    )
    cursor = conn.cursor(dictionary=True)
    query = f"""
    SELECT
        id,
        ts,
        pid,
        tid,
        syscall_num,
        process_name
    FROM {TABLE_NAME}
    WHERE ({where_clause}) AND process_name NOT LIKE "%parsec%" AND process_name NOT LIKE "%dwm%"
    ORDER BY ts ASC, id ASC
    {'LIMIT ' + str(limit)  if limit else ''}
    """

    cursor.execute(query)
    rows = cursor.fetchall()

    cursor.close()
    conn.close()
    return rows





def build_syscall_vocab(windows):
    s = set()
    for w in windows:
        for e in w:
            s.add(e["syscall_num"])

    syscall_to_id = {"<UNK>": 0}
    for i, num in enumerate(sorted(s), start=1):
        syscall_to_id[num] = i

    return syscall_to_id


def base_severity_from_score(score: float) -> str:
    if score < HIGH_THR:
        return "HIGH"
    elif score < MEDIUM_THR:
        return "MEDIUM"
    else:
        return "LOW"


def severity_with_monotonic_downgrade(score: float, syscalls_in_window) -> str:
    """
    Requested change #1:
    If window is monotonic (same syscall repeated 4 times), DOWNGRADE severity.

    - If base is HIGH -> downgrade to MEDIUM
    - If base is MEDIUM -> downgrade to LOW
    - If base is LOW -> keep LOW
    """
    base = base_severity_from_score(score)

    if len(set(syscalls_in_window)) == 1:
        if base == "HIGH":
            return "MEDIUM"
        if base == "MEDIUM":
            return "LOW"
        return "LOW"

    return base


def evaluate_and_report(label: str, windows, X, model, scaler):
    """
    Runs OCSVM on provided windows+features, buckets anomalies, prints:
    - Global severity report
    - Per-PID summary
    - Examples with syscalls printed
    - Alert logic (#2): counts only HIGH anomalies with >1 unique syscall
    """
    X_scaled = scaler.transform(X)
    preds = model.predict(X_scaled)                 # +1 normal, -1 anomaly
    scores = model.decision_function(X_scaled)      # more negative => more anomalous

    severity_buckets = {"LOW": [], "MEDIUM": [], "HIGH": []}
    pid_severity = defaultdict(list)

    high_non_mono_count = 0
    high_non_mono_by_pid = defaultdict(int)

    for i, (p, s) in enumerate(zip(preds, scores)):
        if p != -1:
            continue

        w = windows[i]
        proc_name = w[0]["process_name"]
        pid = w[0]["pid"]
        syscalls = [robocop.convert_syscall_num_to_string(e["syscall_num"]) for e in w]

        sev = severity_with_monotonic_downgrade(float(s), syscalls)

        pid_severity[pid].append(sev)
        severity_buckets[sev].append({
            "pid": pid,
            "name" : proc_name,
            "score": float(s),
            "syscalls": syscalls,
        })

        # Requested change #2: alert counts only HIGH with >1 unique syscall
        if sev == "HIGH" and len(set(syscalls)) > 1:
            high_non_mono_count += 1
            high_non_mono_by_pid[pid] += 1

    # ===== PRINT REPORT =====
    print("\n" + "=" * 70)
    print(f"===== REPORT: {label} =====")
    print("=" * 70)

    total_anom = sum(len(v) for v in severity_buckets.values())
    print("\n===== GLOBAL SEVERITY REPORT =====")
    for k in ["LOW", "MEDIUM", "HIGH"]:
        print(f"{k:>6}: {len(severity_buckets[k])}")
    print(f"Total anomalies: {total_anom}")

    print("\n===== PER-PID SUMMARY =====")
    if not pid_severity:
        print("No anomalous PIDs found.")
    else:
        # sort by #HIGH desc then total desc
        items = []
        for pid, sevs in pid_severity.items():
            c = Counter(sevs)
            items.append((pid, c.get("HIGH", 0), sum(c.values()), c))
        items.sort(key=lambda x: (x[1], x[2]), reverse=True)

        for pid, high_cnt, total_cnt, c in items:
            print(f"PID {pid}: {dict(c)}")

    print("\n===== ALERT LOGIC (HIGH & non-monotonic only) =====")
    print(f"HIGH non-monotonic anomalies: {high_non_mono_count}")
    if high_non_mono_count >= ALERT_HIGH_NON_MONO_THRESHOLD:
        print("🚨 ALERT: High confidence suspicious activity (non-monotonic HIGH anomalies)")
        # show top PIDs by high_non_mono
        top = sorted(high_non_mono_by_pid.items(), key=lambda x: x[1], reverse=True)[:5]
        print("Top suspicious PIDs (by HIGH non-monotonic count):", top)
    else:
        print("✅ No strong alert triggered by rule")

    # Print examples (with syscalls)
    for bucket in ["HIGH", "MEDIUM", "LOW"]:
        print(f"\n===== {bucket} SEVERITY EXAMPLES (showing syscalls) =====")
        ex = severity_buckets[bucket]
        if not ex:
            print(f"No {bucket} anomalies.")
            continue

        for idx, a in enumerate(ex, start=1):
            print("-" * 60)
            print(f"{bucket} #{idx}")
            print(f"PID: {a['pid']} , Name: {a["name"]}")
            print(f"Score: {a['score']:.4f}")
            print("Syscalls:", a["syscalls"])

    return {
        "severity_buckets": severity_buckets,
        "pid_severity": pid_severity,
        "high_non_mono_count": high_non_mono_count,
        "total_anomalies": total_anom,
    }

