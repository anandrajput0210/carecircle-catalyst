"""Authentication and Credential Service for CareCircle."""
import hashlib
import hmac
import logging
import secrets
from typing import Optional

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

logger = logging.getLogger("carecircle.auth")

# Standard Argon2id configuration (OWASP recommended parameters)
# time_cost=2, memory_cost=65536 (64 MiB), parallelism=1, hash_len=32, type=Type.ID
_hasher = PasswordHasher(
    time_cost=2,
    memory_cost=65536,
    parallelism=1,
    hash_len=32,
    type=Type.ID,
)

# Precomputed dummy Argon2id hash for constant-time failed lookups (mitigates timing attacks)
_DUMMY_SECRET = "carecircle-dummy-timing-mitigation-secret"
_DUMMY_HASH = _hasher.hash(_DUMMY_SECRET)

# Unambiguous alphabet for 6-character Circle Codes (excludes 0, O, 1, I)
# Matches ElderLoginRequest pattern: ^[A-HJ-NP-Za-hj-np-z2-9]{6}$
_CIRCLE_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

# Recovery key alphabet (24 characters, high entropy, transcription-friendly)
_RECOVERY_KEY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def hash_credential(secret: str) -> str:
    """
    Compute Argon2id hash for a password, PIN, or recovery key.
    Raw secrets are never logged or stored.
    """
    if not isinstance(secret, str) or not secret:
        raise ValueError("Credential secret must be a non-empty string.")
    return _hasher.hash(secret)


def verify_credential(hash_val: Optional[str], secret: str) -> bool:
    """
    Verify a plaintext secret against an Argon2id hash.
    Safely returns False on mismatch or corrupted hash.
    """
    if not hash_val or not isinstance(hash_val, str) or not secret or not isinstance(secret, str):
        return False
    try:
        return _hasher.verify(hash_val, secret)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    except Exception as e:
        logger.warning(f"Unexpected error during credential verification: {e}")
        return False


def verify_dummy_credential() -> None:
    """
    Execute an Argon2id verification against a dummy hash.
    Ensures execution time for non-existent users is indistinguishable
    from that of existing users (timing attack mitigation).
    """
    try:
        _hasher.verify(_DUMMY_HASH, "incorrect-dummy-candidate")
    except Exception:
        pass


def generate_recovery_key() -> str:
    """
    Generate a cryptographically secure 24-character emergency recovery key.
    Uses unambiguous characters for offline transcription.
    """
    return "".join(secrets.choice(_RECOVERY_KEY_ALPHABET) for _ in range(24))


def generate_session_token() -> str:
    """
    Generate a 32-byte (43-44 char) cryptographically random URL-safe session token.
    The raw token is stored only in the client's HttpOnly cookie.
    """
    return secrets.token_urlsafe(32)


def hash_session_token(token: str) -> str:
    """
    Compute SHA-256 digest of a session token for storage and lookup in Firestore.
    Raw tokens are never stored in the database.
    """
    if not token or not isinstance(token, str):
        raise ValueError("Session token must be a non-empty string.")
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_circle_code() -> str:
    """
    Generate a random 6-character uppercase alphanumeric Circle Code.
    Excludes ambiguous characters (0, O, 1, I).
    """
    return "".join(secrets.choice(_CIRCLE_CODE_ALPHABET) for _ in range(6))


def constant_time_compare(val1: str, val2: str) -> bool:
    """Perform constant-time string comparison to prevent timing side channels."""
    if not isinstance(val1, str) or not isinstance(val2, str):
        return False
    return hmac.compare_digest(val1.encode("utf-8"), val2.encode("utf-8"))
