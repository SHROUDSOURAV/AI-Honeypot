import json
import time
import os
import csv
from collections import defaultdict
from datetime import datetime

LOG_FILE = "/var/lib/docker/volumes/docker_cowrie-var/_data/log/cowrie/cowrie.json"     # my log file location
DATASET_FILE = "dataset.csv"

BATCH_SIZE = 20
FLUSH_INTERVAL = 30  # flush batch every 30 seconds even if not full
batch = []

failed_login_counter = defaultdict(int)
last_command_time = {}
LAST_FLUSH_TIME = time.time()

# =========================
# Initialize CSV
# =========================
# initializes the dataset based on the below mentioned headers
def initialize_dataset():
    if not os.path.exists(DATASET_FILE):
        with open(DATASET_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp",
                "session",
                "src_ip",
                "username",
                "password",
                "command",
                "event_type",
                "command_length",
                "is_root_attempt",
                "failed_login_count",
                "time_since_last_command"
            ])

# =========================
# Feature Engineering
# =========================
def extract_features(log):
    event_id = log.get("eventid")
    timestamp = log.get("timestamp")
    session = log.get("session")
    src_ip = log.get("src_ip")
    username = log.get("username", "")
    password = log.get("password", "")
    command = log.get("input", "")

    command_length = len(command)
    is_root_attempt = 1 if username == "root" else 0

    if event_id == "cowrie.login.failed":   # detect bruteforce attack intensity
        failed_login_counter[src_ip] += 1

    failed_login_count = failed_login_counter[src_ip]   # number of failed attempts as per the attack ip

    # Checks time between commands from the last time commands got entered from this IP address
    # very fast commands -> might indicate automated boot behavior
    # slow commands -> might indicate human attacker
    try:
        current_time = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except Exception:
        current_time = datetime.utcnow()

    if src_ip in last_command_time:
        delta = (current_time - last_command_time[src_ip]).total_seconds()
    else:
        delta = 0

    last_command_time[src_ip] = current_time

    return [
        timestamp,
        session,
        src_ip,
        username,
        password,
        command,
        event_id,
        command_length,
        is_root_attempt,
        failed_login_count,
        delta
    ]

# =========================
# Write Batch to CSV
# =========================
def flush_batch():
    global batch
    if not batch:   # if batch is empty do nothing
        return

    try:
        with open(DATASET_FILE, "a", newline="") as f:  # if batch not empty append batch data to .csv file to model training later
            writer = csv.writer(f)  # creates write object for a csv file
            writer.writerows(batch) # the write object used to add data to the csv file from the batch (here all 20 logs written to csv file at once)
        batch = []  # clean space for the batch variable to prepare for the next 20 logs
    except Exception as e:
        print(f"[!] Error writing to dataset: {e}")

# =========================
# Follow File with Rotation Handling
# =========================
def follow():
    while True:
        try:
            if not os.path.exists(LOG_FILE):
                print("[!] Log file not found. Waiting for Cowrie...")
                time.sleep(5)
                continue

            with open(LOG_FILE, "r") as file:
                file.seek(0, os.SEEK_END)   # read the file from start to finish

                while True:
                    line = file.readline()  # stores a a single line

                    if not line:
                        time.sleep(0.5)
                        continue

                    yield line  # follow() returns a generator object. Each generator object contains multiple new log lines
                                # with yield we get one line at a time or a new log at a time before moving to the next log

        except Exception as e:   # exception handling incase log file not found so tries every 5 seconds
            print(f"[!] Error in follow(): {e}")
            time.sleep(5)

# =========================
# main()
# =========================
def main():
    global LAST_FLUSH_TIME

    print("[+] AI Log Listener Started...")
    initialize_dataset()

    try:
        for line in follow():
            try:
                log = json.loads(line)  # convets json string to python dictionary
            except:
                continue    # if fails to do so then continue

            if log.get("eventid") in [  # filter log based on Important Events
                "cowrie.login.failed",  # bruteforce detection
                "cowrie.login.success", # account compromise
                "cowrie.command.input"  # post-exploitation behavior
            ]:
                row = extract_features(log) # returns 11 datatypes
                batch.append(row)   # stores those 11 datatypes in each single column for a particular log
                                    # so 11 = 1 single log = 1 dataset row for a total for 20 logs

                if len(batch) >= BATCH_SIZE:
                    flush_batch()
                    LAST_FLUSH_TIME = time.time()

            # Flush periodically even if batch not full
            if time.time() - LAST_FLUSH_TIME > FLUSH_INTERVAL:
                flush_batch()
                LAST_FLUSH_TIME = time.time()

    except KeyboardInterrupt:
        print("\n[+] Shutting down cleanly...")
        flush_batch()

if __name__ == "__main__":
    main()