"""L1 — password hashing. Pure computation, no I/O.

WHY scrypt AND NOT argon2
argon2id is the current OWASP first choice and it is a better algorithm. It is
also a dependency, and §3 requires a measured constraint before adding one.
`hashlib.scrypt` is in the standard library, is a memory-hard KDF designed for
exactly this, and is accepted by OWASP as a valid second choice. For a system
with no users yet, taking the stdlib option is the Simplicity-First answer.

WHAT MAKES THAT DECISION CHEAP TO REVERSE
The stored string carries its own algorithm and parameters:

    scrypt$n=16384,r=8,p=1$<salt base64>$<derived key base64>

Verification dispatches on what is stored, never on what is current. So adding
argon2 later means adding a branch and a new default — existing passwords keep
verifying under scrypt and are upgraded on next login, with no reset email to
anyone. The migration cost is paid once, here, in the format.

This is the same reasoning as the TSA: the provider is configuration, and the
stored artifact records which one produced it.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass

#: OWASP's floor for scrypt is n=2^14, r=8, p=1 with a 32-byte output. Held
#: here as the current default rather than assumed everywhere: raising it later
#: must not invalidate hashes written under the old cost.
DEFAULT_N = 16384
DEFAULT_R = 8
DEFAULT_P = 1
SALT_BYTES = 16
KEY_BYTES = 32

SCRYPT = "scrypt"


class PasswordError(ValueError):
    """A password could not be hashed or a stored hash could not be read."""


@dataclass(frozen=True, slots=True)
class StoredHash:
    algorithm: str
    parameters: dict[str, int]
    salt: bytes
    digest: bytes

    def serialise(self) -> str:
        params = ",".join(f"{k}={v}" for k, v in sorted(self.parameters.items()))
        return "$".join(
            [
                self.algorithm,
                params,
                base64.b64encode(self.salt).decode("ascii"),
                base64.b64encode(self.digest).decode("ascii"),
            ]
        )

    @classmethod
    def parse(cls, stored: str) -> StoredHash:
        parts = stored.split("$")
        if len(parts) != 4:
            raise PasswordError("stored password hash is not in algorithm$params$salt$digest form")
        algorithm, raw_params, salt, digest = parts

        parameters: dict[str, int] = {}
        for pair in raw_params.split(","):
            if not pair:
                continue
            name, _, value = pair.partition("=")
            if not value.isdigit():
                raise PasswordError(f"non-numeric KDF parameter {pair!r}")
            parameters[name] = int(value)

        try:
            return cls(algorithm, parameters, base64.b64decode(salt), base64.b64decode(digest))
        except Exception as exc:
            raise PasswordError(f"stored password hash is unreadable: {exc}") from exc


def hash_password(
    password: str, *, n: int = DEFAULT_N, r: int = DEFAULT_R, p: int = DEFAULT_P
) -> str:
    """Derive a new hash with a fresh random salt."""
    if not password:
        raise PasswordError("refusing to hash an empty password")

    salt = secrets.token_bytes(SALT_BYTES)
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=KEY_BYTES, maxmem=n * r * 256
    )
    return StoredHash(SCRYPT, {"n": n, "r": r, "p": p}, salt, digest).serialise()


def verify_password(password: str, stored: str) -> bool:
    """Check a password against a stored hash.

    Comparison is `hmac.compare_digest`, not `==`. A naive comparison returns
    faster on an early mismatch, and that timing difference is enough to
    recover a digest byte by byte given enough attempts.
    """
    try:
        parsed = StoredHash.parse(stored)
    except PasswordError:
        return False

    if parsed.algorithm != SCRYPT:
        # A future argon2 branch lands here. Returning False rather than raising
        # keeps an unknown algorithm from becoming an authentication bypass in
        # any caller that treats an exception as "not our problem".
        return False

    try:
        candidate = hashlib.scrypt(
            password.encode("utf-8"),
            salt=parsed.salt,
            n=parsed.parameters["n"],
            r=parsed.parameters["r"],
            p=parsed.parameters["p"],
            dklen=len(parsed.digest),
            maxmem=parsed.parameters["n"] * parsed.parameters["r"] * 256,
        )
    except (KeyError, ValueError):
        return False

    return hmac.compare_digest(candidate, parsed.digest)


def needs_rehash(stored: str, *, n: int = DEFAULT_N) -> bool:
    """True when the stored hash is weaker than the current default.

    Called after a successful login so cost can be raised over time without
    asking anyone to reset a password — the upgrade happens while the plaintext
    is legitimately in hand, which is the only moment it can.
    """
    try:
        parsed = StoredHash.parse(stored)
    except PasswordError:
        return True
    return parsed.algorithm != SCRYPT or parsed.parameters.get("n", 0) < n


def new_session_token() -> str:
    """A session token. 256 bits from the OS CSPRNG.

    Returned to the caller once; only its SHA-256 is ever stored, so a database
    dump yields no usable session.
    """
    return secrets.token_urlsafe(32)


def token_fingerprint(token: str) -> str:
    """The stored form of a session token.

    Plain SHA-256 with no salt, deliberately: this must be *looked up*, and a
    per-row salt would force a scan of every session on every request. It is
    safe here precisely because the input is 256 bits of CSPRNG output — there
    is no dictionary to attack, which is what makes passwords different.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
