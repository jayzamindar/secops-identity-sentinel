"""
Cryptographic HMAC-SHA256 Signing, Anti-Replay TTL Verification & Idempotency.

Adheres strictly to GEMINI.md Sections 3.3 & 3.4 and TRD.md Sections 3.1 & 3.2:
  - Canonical JSON serialization with sorted keys and compact separators.
  - SHA-256 plan digest and HMAC-SHA256 signature computation.
  - Constant-time signature verification via hmac.compare_digest().
  - Anti-replay TTL ceiling enforcement (<= 300 seconds).
  - Monotonic plan_id / idempotency_key deduplication store.
  - Fail-closed RuntimeError on missing or insecure secrets in production.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import threading
from datetime import UTC, datetime
from typing import Any

from secops_identity_sentinel.config import get_settings
from secops_identity_sentinel.models.plan import SignedRemediationPlan

logger = logging.getLogger(__name__)

INSECURE_SECRET_MARKERS: list[str] = [
    "change_me",
    "default",
    "insecure",
    "dev_secret",
    "test_secret",
]

FALLBACK_DEV_SECRET: str = "dev-insecure-plan-signing-secret-do-not-use-in-prod"


def canonical_serialize(plan: SignedRemediationPlan | dict[str, Any]) -> bytes:
    """
    Serialize a remediation plan into canonical deterministic UTF-8 JSON bytes.

    Excludes 'plan_digest' and 'plan_signature' to produce the pre-signature digest input.
    Enforces sorted keys, compact separators (',', ':'), and ensure_ascii=False.

    Args:
        plan: SignedRemediationPlan instance or dictionary payload.

    Returns:
        bytes: Canonical UTF-8 encoded byte string.
    """
    raw_dict: dict[str, Any]
    if isinstance(plan, SignedRemediationPlan):
        raw_dict = plan.model_dump(mode="json", exclude={"plan_digest", "plan_signature"})
    elif isinstance(plan, dict):
        raw_dict = {k: v for k, v in plan.items() if k not in ("plan_digest", "plan_signature")}
    else:
        raise TypeError(f"Unsupported plan type for serialization: {type(plan)}")

    canonical_str = json.dumps(
        raw_dict,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return canonical_str.encode("utf-8")


def resolve_signing_secret(secret: str | None = None) -> str:
    """
    Resolve cryptographic secret with strict fail-closed enforcement in production.

    Raises:
        RuntimeError: If running in production and secret is empty, missing, or insecure.
    """
    env = os.environ.get("ENVIRONMENT")
    if not env:
        try:
            env = str(get_settings().environment)
        except Exception:
            env = "development"

    resolved_secret = secret
    if resolved_secret is None or not resolved_secret.strip():
        if "PLAN_SIGNING_SECRET" in os.environ:
            resolved_secret = os.environ.get("PLAN_SIGNING_SECRET", "")
        else:
            try:
                resolved_secret = get_settings().plan_signing_secret
            except Exception:
                resolved_secret = ""

    cleaned = (resolved_secret or "").strip()

    if env.strip().lower() == "production":
        lower = cleaned.lower()
        if not cleaned or any(m in lower for m in INSECURE_SECRET_MARKERS):
            raise RuntimeError(
                "Production security violation: PLAN_SIGNING_SECRET must be configured "
                "with a strong, non-default cryptographic secret."
            )

    if not cleaned:
        cleaned = FALLBACK_DEV_SECRET

    return cleaned


def compute_plan_digest(plan: SignedRemediationPlan | dict[str, Any]) -> str:
    """
    Compute canonical SHA-256 digest of remediation plan payload.

    Args:
        plan: SignedRemediationPlan or dictionary representation.

    Returns:
        str: Hexadecimal SHA-256 digest string.
    """
    canonical_bytes = canonical_serialize(plan)
    return hashlib.sha256(canonical_bytes).hexdigest()


def compute_plan_signature(
    plan: SignedRemediationPlan | dict[str, Any],
    secret: str,
) -> str:
    """
    Compute HMAC-SHA256 cryptographic signature over canonical plan bytes.

    Args:
        plan: SignedRemediationPlan or dictionary representation.
        secret: Signing secret key string.

    Returns:
        str: Hexadecimal HMAC-SHA256 signature string.
    """
    canonical_bytes = canonical_serialize(plan)
    return hmac.new(
        key=secret.encode("utf-8"),
        msg=canonical_bytes,
        digestmod=hashlib.sha256,
    ).hexdigest()


def sign_remediation_plan(
    plan: SignedRemediationPlan,
    secret: str | None = None,
) -> SignedRemediationPlan:
    """
    Seal a remediation plan with SHA-256 digest and HMAC-SHA256 signature.

    Args:
        plan: Remediation plan to be cryptographically sealed.
        secret: Optional secret override. If omitted, resolved from configuration.

    Returns:
        SignedRemediationPlan: New instance with plan_digest and plan_signature populated.

    Raises:
        RuntimeError: If secret is missing or insecure in production mode.
    """
    resolved_secret = resolve_signing_secret(secret)
    digest = compute_plan_digest(plan)
    signature = compute_plan_signature(plan, resolved_secret)

    return plan.model_copy(
        update={
            "plan_digest": digest,
            "plan_signature": signature,
        }
    )


def verify_plan_signature(
    plan: SignedRemediationPlan,
    secret: str | None = None,
    now: datetime | None = None,
) -> bool:
    """
    Verify HMAC-SHA256 signature, SHA-256 digest, and anti-replay TTL expiration.

    Uses constant-time comparison (hmac.compare_digest) to prevent timing side-channels.

    Args:
        plan: Sealed remediation plan to verify.
        secret: Optional secret override.
        now: Optional current UTC timestamp override for testing TTL bounds.

    Returns:
        bool: True if signature and digest match and plan is not expired, False otherwise.
    """
    if not plan.plan_digest or not plan.plan_signature:
        logger.warning(
            "Plan verification failed: empty digest or signature for plan '%s'",
            plan.plan_id,
        )
        return False

    current_time = now if now is not None else datetime.now(UTC)
    if current_time.tzinfo is None:
        current_time = current_time.replace(tzinfo=UTC)

    plan_exp = plan.expires_at
    if plan_exp.tzinfo is None:
        plan_exp = plan_exp.replace(tzinfo=UTC)

    # Anti-Replay: enforce TTL window (expired plans fail closed)
    if current_time >= plan_exp:
        logger.warning(
            "Plan verification failed: Plan '%s' expired at %s (current: %s)",
            plan.plan_id,
            plan_exp.isoformat(),
            current_time.isoformat(),
        )
        return False

    try:
        resolved_secret = resolve_signing_secret(secret)
    except RuntimeError as exc:
        logger.error("Plan verification failed on secret resolution: %s", exc)
        return False

    expected_digest = compute_plan_digest(plan)
    expected_signature = compute_plan_signature(plan, resolved_secret)

    digest_ok = hmac.compare_digest(plan.plan_digest, expected_digest)
    sig_ok = hmac.compare_digest(plan.plan_signature, expected_signature)

    if not (digest_ok and sig_ok):
        logger.warning(
            "Plan verification failed: Cryptographic signature/digest mismatch for plan '%s'",
            plan.plan_id,
        )
        return False

    return True


class PlanIdempotencyRegistry:
    """
    Thread-safe deduplication and anti-replay cache for signed remediation plans.

    Ensures that replayed or duplicate remediation requests within the TTL window
    return the cached signed plan without re-executing state mutations or ledger events.
    """

    MAX_ENTRIES: int = 10000

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_idempotency_key: dict[str, SignedRemediationPlan] = {}
        self._by_plan_id: dict[str, SignedRemediationPlan] = {}

    def record_plan(self, plan: SignedRemediationPlan) -> None:
        """
        Record a signed plan in the idempotency registry, pruning expired entries when full.
        """
        with self._lock:
            if len(self._by_idempotency_key) >= self.MAX_ENTRIES:
                now = datetime.now(UTC)
                expired_keys = [
                    k
                    for k, p in self._by_idempotency_key.items()
                    if now
                    >= (p.expires_at if p.expires_at.tzinfo else p.expires_at.replace(tzinfo=UTC))
                ]
                for k in expired_keys:
                    removed = self._by_idempotency_key.pop(k, None)
                    if removed is not None:
                        self._by_plan_id.pop(removed.plan_id, None)
                if len(self._by_idempotency_key) >= self.MAX_ENTRIES:
                    oldest_key = next(iter(self._by_idempotency_key))
                    removed = self._by_idempotency_key.pop(oldest_key)
                    self._by_plan_id.pop(removed.plan_id, None)

            self._by_idempotency_key[plan.idempotency_key] = plan
            self._by_plan_id[plan.plan_id] = plan

    def get_by_idempotency_key(
        self,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> SignedRemediationPlan | None:
        """
        Retrieve cached plan by idempotency key if not expired.
        """
        current_time = now if now is not None else datetime.now(UTC)
        if current_time.tzinfo is None:
            current_time = current_time.replace(tzinfo=UTC)

        with self._lock:
            plan = self._by_idempotency_key.get(idempotency_key)
            if plan is None:
                return None

            plan_exp = plan.expires_at
            if plan_exp.tzinfo is None:
                plan_exp = plan_exp.replace(tzinfo=UTC)

            if current_time >= plan_exp:
                # Expired: purge from registry
                self._by_idempotency_key.pop(idempotency_key, None)
                self._by_plan_id.pop(plan.plan_id, None)
                return None

            return plan

    def get_by_plan_id(
        self,
        plan_id: str,
        now: datetime | None = None,
    ) -> SignedRemediationPlan | None:
        """
        Retrieve cached plan by plan_id if not expired.
        """
        current_time = now if now is not None else datetime.now(UTC)
        if current_time.tzinfo is None:
            current_time = current_time.replace(tzinfo=UTC)

        with self._lock:
            plan = self._by_plan_id.get(plan_id)
            if plan is None:
                return None

            plan_exp = plan.expires_at
            if plan_exp.tzinfo is None:
                plan_exp = plan_exp.replace(tzinfo=UTC)

            if current_time >= plan_exp:
                self._by_plan_id.pop(plan_id, None)
                self._by_idempotency_key.pop(plan.idempotency_key, None)
                return None

            return plan

    def is_known(self, key_or_id: str, now: datetime | None = None) -> bool:
        """
        Check if key or plan ID has already been recorded and remains unexpired.
        """
        return (
            self.get_by_idempotency_key(key_or_id, now=now) is not None
            or self.get_by_plan_id(key_or_id, now=now) is not None
        )

    def reset(self) -> None:
        """
        Clear all entries from the registry.
        """
        with self._lock:
            self._by_idempotency_key.clear()
            self._by_plan_id.clear()


# Process-level singleton idempotency registry
default_idempotency_registry: PlanIdempotencyRegistry = PlanIdempotencyRegistry()


__all__: list[str] = [
    "canonical_serialize",
    "compute_plan_digest",
    "compute_plan_signature",
    "resolve_signing_secret",
    "sign_remediation_plan",
    "verify_plan_signature",
    "PlanIdempotencyRegistry",
    "default_idempotency_registry",
]
