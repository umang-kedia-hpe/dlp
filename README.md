# dlp

## Overview

This project implements Data Loss Prevention (DLP) for Kubernetes workloads using dedicated ingress and egress sidecar containers. The architecture enables real-time, bidirectional inspection and enforcement of DLP policies at the pod level, with dynamic policy updates and minimal impact on application performance.

## Features

- **Bidirectional DLP:** Inspects both incoming and outgoing traffic.
- **Dynamic Policy Reload:** Update DLP patterns via ConfigMap without restarting pods.
- **No App Changes:** Transparent to the main application.
- **Extensible Patterns:** Supports PII, secrets, SQL injection, command injection, and more.

## Architecture

- **Ingress Sidecar:** FastAPI-based proxy (can be implemented in any language or framework) that inspects and enforces DLP policies on incoming traffic.
- **Egress Sidecar:** mitmproxy-based proxy (can be implemented in any language or framework) that inspects and enforces DLP policies on outgoing traffic.
- **ConfigMap:** Stores DLP patterns (regexes) and is mounted into both sidecars for real-time enforcement.

## Example DLP Pattern (ConfigMap)

```json
{
  "type": "pii",
  "name": "US SSN",
  "pattern": "\\b\\d{3}-\\d{2}-\\d{4}\\b",
  "action": "block",
  "description": "US Social Security Number"
}
```

## Usage

1. Deploy the Kubernetes manifests (`Deployment`, `Service`, `ConfigMap`).
2. Update `patterns.json` in the ConfigMap to add or modify DLP rules.
3. The sidecars will automatically reload policies and enforce them on all traffic.

## Proof of Concept

A working PoC is available. Please contact the maintainer if you would like to see the running code or a live demonstration.

---
```<!-- filepath: /Users/kediau/Desktop/workspace/dlp/README.md -->
# dlp

## Overview

This project implements Data Loss Prevention (DLP) for Kubernetes workloads using dedicated ingress and egress sidecar containers. The architecture enables real-time, bidirectional inspection and enforcement of DLP policies at the pod level, with dynamic policy updates and minimal impact on application performance.

## Features

- **Bidirectional DLP:** Inspects both incoming and outgoing traffic.
- **Dynamic Policy Reload:** Update DLP patterns via ConfigMap without restarting pods.
- **No App Changes:** Transparent to the main application.
- **Extensible Patterns:** Supports PII, secrets, SQL injection, command injection, and more.

## Architecture

- **Ingress Sidecar:** FastAPI-based proxy (can be implemented in any language or framework) that inspects and enforces DLP policies on incoming traffic.
- **Egress Sidecar:** mitmproxy-based proxy (can be implemented in any language or framework) that inspects and enforces DLP policies on outgoing traffic.
- **ConfigMap:** Stores DLP patterns (regexes) and is mounted into both sidecars for real-time enforcement.

## Example DLP Pattern (ConfigMap)

```json
{
  "type": "pii",
  "name": "US SSN",
  "pattern": "\\b\\d{3}-\\d{2}-\\d{4}\\b",
  "action": "block",
  "description": "US Social Security Number"
}
```

## Usage

1. Deploy the Kubernetes manifests (`Deployment`, `Service`, `ConfigMap`).
2. Update `patterns.json` in the ConfigMap to add or modify DLP rules.
3. The sidecars will automatically reload policies and enforce them on all traffic.

## Proof of Concept

A working PoC is available. Please contact the maintainer if you would like to see the running code or a live demonstration.

---