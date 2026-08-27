"""Signed, expiring session capability tokens."""

import base64
import hashlib
import hmac
from datetime import UTC, datetime

from avo_correlate.contracts.tools import CapabilityClaims
from avo_correlate.domain.canonical import canonical_bytes


class InvalidCapabilityToken(ValueError):
    pass


class CapabilityIssuer:
    def __init__(self, signing_key: bytes) -> None:
        if len(signing_key) < 32:
            raise ValueError("capability signing key must contain at least 32 bytes")
        self._key = signing_key

    def issue(self, claims: CapabilityClaims) -> str:
        payload = canonical_bytes(claims)
        signature = hmac.digest(self._key, payload, hashlib.sha256)
        return f"v1.{_encode(payload)}.{_encode(signature)}"

    def verify(
        self,
        token: str,
        *,
        session_id: str,
        workspace_digest: str,
        tool_id: str,
        now: datetime | None = None,
    ) -> CapabilityClaims:
        try:
            version, encoded_payload, encoded_signature = token.split(".")
            payload = _decode(encoded_payload)
            signature = _decode(encoded_signature)
        except (ValueError, UnicodeError) as exc:
            raise InvalidCapabilityToken("malformed capability token") from exc
        if version != "v1":
            raise InvalidCapabilityToken("unsupported capability token version")
        expected = hmac.digest(self._key, payload, hashlib.sha256)
        if not hmac.compare_digest(signature, expected):
            raise InvalidCapabilityToken("invalid capability token signature")
        try:
            claims = CapabilityClaims.model_validate_json(payload)
        except ValueError as exc:
            raise InvalidCapabilityToken("invalid capability claims") from exc
        checked_at = now or datetime.now(UTC)
        if claims.expires_at <= checked_at:
            raise InvalidCapabilityToken("capability token expired")
        if claims.session_id != session_id:
            raise InvalidCapabilityToken("capability token belongs to another session")
        if claims.workspace_digest != workspace_digest:
            raise InvalidCapabilityToken("capability token belongs to another workspace")
        if tool_id not in claims.tools:
            raise InvalidCapabilityToken("tool is not granted by capability token")
        return claims


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.b64decode(value + padding, altchars=b"-_", validate=True)
