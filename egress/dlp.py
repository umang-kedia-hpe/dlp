import os
import threading
from mitmproxy import http
from utilkit import load_patterns, inspect_data

POLICY_PATH = os.environ["DLP_POLICY_PATH"]

DLP_PATTERNS = []
DLP_PATTERNS_MTIME = 0
DLP_PATTERNS_LOCK = threading.Lock()

def get_patterns():
    global DLP_PATTERNS, DLP_PATTERNS_MTIME
    try:
        mtime = os.path.getmtime(POLICY_PATH)
        with DLP_PATTERNS_LOCK:
            if not DLP_PATTERNS or mtime != DLP_PATTERNS_MTIME:
                DLP_PATTERNS = load_patterns(POLICY_PATH)
                DLP_PATTERNS_MTIME = mtime
    except Exception as e:
        print(f"Error loading patterns: {e}")
        # Keep previous DLP_PATTERNS if error occurs
    return DLP_PATTERNS

def request(flow: http.HTTPFlow):
    if flow.request.text:
        patterns = get_patterns()
        findings, masked = inspect_data(flow.request.text, patterns)
        if any(action == "block" for _, action in findings):
            flow.response = http.Response.make(
                403,
                f"Blocked by DLP in request: found {', '.join(label for label, _ in findings)}",
                {"Content-Type": "text/plain"}
            )
        elif any(action == "mask" for _, action in findings):
            flow.request.text = masked

def response(flow: http.HTTPFlow):
    if flow.response and flow.response.text:
        patterns = get_patterns()
        findings, masked = inspect_data(flow.response.text, patterns)
        if any(action == "block" for _, action in findings):
            flow.response = http.Response.make(
                403,
                f"Blocked by DLP in response: found {', '.join(label for label, _ in findings)}",
                {"Content-Type": "text/plain"}
            )
        elif any(action == "mask" for _, action in findings):
            flow.response.text = masked