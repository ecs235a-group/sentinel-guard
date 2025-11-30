import json
import sys
import time


def log(event: dict):
    evt = {"ts": time.time(), **event}
    sys.stderr.write(json.dumps(evt, ensure_ascii=False) + "\n")
    sys.stderr.flush()
