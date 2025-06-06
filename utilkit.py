import re
import json
import logging

logger = logging.getLogger("dlp-utilkit")

def load_patterns(policy_path):
    patterns = []
    try:
        with open(policy_path) as f:
            policy_list = json.load(f)
            for entry in policy_list:
                try:
                    pattern = re.compile(entry["pattern"])
                    label = entry.get("name", entry.get("type", "UNKNOWN"))
                    action = entry.get("action", "block")
                    patterns.append((pattern, label, action))
                except re.error as re_err:
                    logger.warning(f"Invalid regex in policy '{entry}': {re_err}")
    except Exception as e:
        logger.error(f"Failed to load DLP policies from {policy_path}: {e}")
    return patterns

def inspect_data(data, patterns):
    findings = []
    masked_data = data
    for pattern, label, action in patterns:
        for match in pattern.finditer(data):
            findings.append((label, action))
            if action == "mask":
                masked_data = pattern.sub("***", masked_data)
    return findings, masked_data