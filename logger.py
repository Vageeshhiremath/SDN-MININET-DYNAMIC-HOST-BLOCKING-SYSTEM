import json
import time

LOG_FILE = "events.json"

def log_event(event):
    event["timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")
