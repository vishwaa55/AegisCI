"""
Controlled Security Fixtures inspired by OWASP Juice Shop Vulnerability Patterns.

These fixtures isolate representative server-side vulnerability patterns
that Semgrep detects reliably, providing a controlled test target for
AegisCI's Attacker, Defender A, Defender B, and Judge agents.
"""

import hashlib
import os
import sqlite3
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Vulnerability Pattern 1: SQL Injection (OWASP A03:2021, CWE-89)
# Modeled after Juice Shop Product Search SQLi
# ---------------------------------------------------------------------------
def search_products(query: str, db_connection: Optional[sqlite3.Connection] = None) -> List[Dict[str, Any]]:
    """
    Search product catalog by name.
    VULNERABILITY: Direct string interpolation into raw SQL query.
    Expected remediation: Parameterized query (cursor.execute('... WHERE name LIKE ?', (param,)))
    """
    conn = db_connection or sqlite3.connect(":memory:")
    cursor = conn.cursor()
    # Semgrep rule: python.lang.security.audit.formatted-sql-query
    sql = f"SELECT id, name, price, description FROM products WHERE name LIKE '%{query}%' AND deleted = 0"
    cursor.execute(sql)
    rows = cursor.fetchall()
    return [{"id": r[0], "name": r[1], "price": r[2], "description": r[3]} for r in rows]


# ---------------------------------------------------------------------------
# Vulnerability Pattern 2: Hardcoded Secret / Key (OWASP A02:2021, CWE-798)
# Modeled after Juice Shop hardcoded JWT encryption secret
# ---------------------------------------------------------------------------
# Semgrep rule: generic.secrets.security.detected-jwt-secret / hardcoded-key
STATIC_JWT_SECRET = "owasp_juice_shop_jwt_super_secret_signing_key_2026"


def verify_auth_token(token: str) -> bool:
    """
    Verify client authentication token.
    VULNERABILITY: Relies on hardcoded symmetric secret key in source code.
    Expected remediation: Read secret from environment variable (e.g. os.getenv("JWT_SECRET_KEY"))
    """
    secret = STATIC_JWT_SECRET
    return bool(token and token.startswith(f"{secret}:"))


# ---------------------------------------------------------------------------
# Vulnerability Pattern 3: Path Traversal (OWASP A01:2021, CWE-22)
# Modeled after Juice Shop easter egg file retrieval
# ---------------------------------------------------------------------------
def retrieve_public_document(filename: str, base_directory: str = "/var/public_docs") -> str:
    """
    Retrieve document from public directory.
    VULNERABILITY: Insecure os.path.join without path containment verification.
    Expected remediation: Validate normalized path starts with base_directory.
    """
    # Semgrep rule: python.lang.security.audit.path-traversal
    target_path = os.path.join(base_directory, filename)
    if os.path.exists(target_path):
        with open(target_path, "r", encoding="utf-8") as f:
            return f.read()
    return ""


# ---------------------------------------------------------------------------
# Vulnerability Pattern 4: Weak Cryptographic Hash (OWASP A02:2021, CWE-327)
# Modeled after Juice Shop legacy user password hashing
# ---------------------------------------------------------------------------
def hash_user_password(password: str, salt: str = "") -> str:
    """
    Hash a user password.
    VULNERABILITY: Uses broken MD5 digest instead of modern Argon2 or bcrypt.
    Expected remediation: Use secure hash (e.g. hashlib.sha256 or bcrypt)
    """
    # Semgrep rule: python.lang.security.audit.insecure-hash-algorithm-md5
    hasher = hashlib.md5()
    hasher.update((password + salt).encode("utf-8"))
    return hasher.hexdigest()
