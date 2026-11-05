# OWASP Juice Shop Security Harness for AegisCI

This directory contains the controlled security experimentation target modeled on OWASP Juice Shop vulnerability patterns.

---

## 1. Local OWASP Juice Shop Container (Optional Standalone Target)

To launch the real OWASP Juice Shop container locally:

```powershell
# Start local Juice Shop container bound strictly to localhost (127.0.0.1)
docker run -d --name aegis-juice-shop -p 127.0.0.1:3000:3000 --rm bkimminich/juice-shop:v17.1.1

# Verify container is running
docker ps --filter "name=aegis-juice-shop"

# Stop local Juice Shop container
docker stop aegis-juice-shop
```

> **Security & Network Boundary**: The container binds strictly to loopback interface `127.0.0.1:3000`. It is never exposed on external networks or public interfaces.

---

## 2. Controlled Vulnerability Fixtures

Full-scale enterprise apps like Juice Shop contain mixed TypeScript/Angular frontends and dynamic Node.js backends. For deterministic, reproducible evaluation of AegisCI's multi-agent security pipeline:

- `experiments/juice_shop/fixtures/vulnerable_services.py` isolates 4 classic server-side security patterns:
  1. **SQL Injection (CWE-89, OWASP A03:2021)**: Raw string interpolation in database query (modeled after Juice Shop product catalog search).
  2. **Hardcoded Secret (CWE-798, OWASP A02:2021)**: Static JWT symmetric encryption key in source code.
  3. **Path Traversal (CWE-22, OWASP A01:2021)**: Unrestricted relative file path concatenation.
  4. **Weak Cryptography (CWE-327, OWASP A02:2021)**: Broken MD5 digest used for password verification.

---

## 3. Baseline Semgrep Scan

The baseline static analysis scan was executed using:

```powershell
semgrep --config=auto --json experiments/juice_shop/fixtures/vulnerable_services.py > experiments/juice_shop/baseline_scan.json
```

### Baseline Findings Recorded in `baseline_scan.json`

| Rule ID | Severity | File | Line | CWE / OWASP |
|---|---|---|---|---|
| `python.lang.security.audit.formatted-sql-query` | WARNING | `vulnerable_services.py` | 29 | CWE-89 (SQL Injection), OWASP A03:2021 |
| `python.sqlalchemy.security.sqlalchemy-execute-raw-query` | ERROR | `vulnerable_services.py` | 29 | CWE-89 (SQL Injection), OWASP A03:2021 |

### SAST Limitations & Scope Boundary
Semgrep is a Static Application Security Testing (SAST) tool. It statically checks code patterns and taint flows. It does not replace dynamic application security testing (DAST) or runtime vulnerability scanning. AegisCI uses Semgrep findings as evidence for the Attacker, Defender A, Defender B, and Judge agents.

---

## 4. Running the Security Debate Workflow

To run the full multi-agent debate workflow against the baseline findings:

```powershell
python -m experiments.juice_shop.run_security_experiment
```
