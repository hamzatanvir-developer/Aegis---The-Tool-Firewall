# Aegis Product Security & Architecture Hardening

Aegis is designed to operate as a critical security control inside agentic runtimes. As a firewall, Aegis itself must maintain a zero-trust posture, minimal attack surface, and fail-safe operation.

---

## 1. Core Security Guarantees

### 🛡️ 1. Fail-Closed Default Execution
* **Behavior:** If the policy evaluation engine encounters an unhandled exception, syntax error in policy YAML, or memory timeout, Aegis automatically defaults to **FAIL-CLOSED** (blocking the tool call and raising `PolicyViolationError`).
* **Guarantee:** Uninspected payloads are **never** permitted to execute downstream.

### 📦 2. Minimal Attack Surface & Zero-Supply Chain Vulnerability
* **Dependency Hygiene:** The core interception logic (`aegis.core`, `aegis.engine`) relies exclusively on the Python Standard Library (`re`, `functools`, `json`, `typing`).
* **Guarantee:** Eliminates third-party dependency vulnerabilities, supply chain hijacking, and transitive package bloat.

### ⚡ 3. ReDoS (Regular Expression Denial of Service) Defense
* **Pattern Hardening:** All regex rules for SQL injection, command chaining, and PII matching are compiled with linear time-complexity patterns.
* **Guarantee:** Malicious agent payloads cannot cause CPU starvation or freeze the Python event loop through catastrophic backtracking.

### 🔒 4. In-Memory Execution & Zero-Data Exposure
* **Data Isolation:** Argument inspection occurs entirely in-memory within the host application process. 
* **Guarantee:** Raw inputs, unredacted secrets, and API payloads are never sent to third-party SaaS vendors or external LLM evaluation endpoints.

### 🧬 5. Argument Immutability & Memory Safety
* **Safe Mutability:** Intercepted positional (`*args`) and keyword arguments (`**kwargs`) are sanitized using isolated deep copies.
* **Guarantee:** Redaction mutates only the outgoing tool call payload without corrupting state or object references in parent execution contexts.

---

## 2. Threat Model & Mitigations

| Threat Vector | Risk Description | Aegis Mitigation |
| :--- | :--- | :--- |
| **Bypass via Obfuscation** | Agent attempts SQL/Shell encoding (`HEX`, `BASE64`, Unicode escapes) | String arguments are unescaped and normalized before pattern matching. |
| **Denial of Service (DoS)** | Large payload processing causing latency spikes | Enforcement of maximum argument length checks prior to regex evaluation. |
| **Secret Leakage in Logs** | Credentials stored in application trace logs | Inline redaction happens *before* function invocation or audit log ingestion. |
| **Policy Modification** | Adversarial agent changing security rules | Security policies are stored read-only in memory or loaded via cryptographically signed DB records. |


## 3. Vulnerability Disclosure

To report security bugs or policy bypass techniques found in Aegis, please email the maintainer or submit a private report via the GitHub **Security** tab. Do not open public issues for zero-day vulnerabilities.