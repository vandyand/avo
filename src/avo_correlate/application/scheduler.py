"""Single-host scheduler with renewable, fenced leases and phase-aware recovery."""

import asyncio
import inspect
from collections.abc import Awaitable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol, cast

from avo_correlate.adapters.persistence.models import ActivityRow
from avo_correlate.application.activity_service import ActivityConflictError, ActivityService


@dataclass(frozen=True)
class ActivityResult:
    result_digest: str


class RecoveryDisposition(StrEnum):
    DURABLE_RESULT = "durable_result"
    NOT_STARTED = "not_started"
    RESUMABLE = "resumable"
    AMBIGUOUS = "ambiguous"


class FailureDisposition(StrEnum):
    RETRY = "retry"
    RECONCILE = "reconcile"


@dataclass(frozen=True)
class ActivityRecovery:
    disposition: RecoveryDisposition
    result: ActivityResult | None = None

    def __post_init__(self) -> None:
        if (self.disposition == RecoveryDisposition.DURABLE_RESULT) != (
            self.result is not None
        ):
            raise ValueError("only durable-result recovery carries a result")


class ActivityHandler(Protocol):
    def recover(
        self, activity: ActivityRow
    ) -> ActivityRecovery | Awaitable[ActivityRecovery]: ...

    def execute(
        self, activity: ActivityRow, lease_epoch: int
    ) -> ActivityResult | Awaitable[ActivityResult]: ...

    def classify_failure(
        self, activity: ActivityRow, error: Exception
    ) -> FailureDisposition: ...


class InjectedWorkerCrash(RuntimeError):
    pass


class Scheduler:
    def __init__(
        self,
        activities: ActivityService,
        *,
        worker_id: str,
        lease_seconds: int = 30,
    ) -> None:
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        self._activities = activities
        self._worker_id = worker_id
        self._lease_seconds = lease_seconds
        self._handlers: dict[str, ActivityHandler] = {}

    def register(self, activity_kind: str, handler: ActivityHandler) -> None:
        if not activity_kind or ":" in activity_kind:
            raise ValueError("activity kind must be a non-empty prefix")
        self._handlers[activity_kind] = handler

    def run_once(self, *, crash_after_external_result: bool = False) -> bool:
        """Synchronous entrypoint retained for single-process workers and tests."""
        return asyncio.run(
            self.run_once_async(crash_after_external_result=crash_after_external_result)
        )

    async def run_once_async(self, *, crash_after_external_result: bool = False) -> bool:
        activity = self._activities.claim_next(
            worker_id=self._worker_id, lease_seconds=self._lease_seconds
        )
        if activity is None:
            return False
        lease_epoch = activity.lease_epoch
        kind = activity.activity_key.partition(":")[0]
        handler = self._handlers.get(kind)
        if handler is None:
            self._activities.mark_reconciliation_required(
                activity.activity_id,
                actor_id=self._worker_id,
                lease_epoch=lease_epoch,
                error={"reason": "handler_not_registered", "activity_kind": kind},
            )
            return True

        recovery = await self._recover(handler, activity)
        if recovery.disposition == RecoveryDisposition.AMBIGUOUS:
            self._activities.mark_reconciliation_required(
                activity.activity_id,
                actor_id=self._worker_id,
                lease_epoch=lease_epoch,
                error={"reason": "ambiguous_external_state"},
            )
            return True

        heartbeat = asyncio.create_task(self._heartbeat(activity.activity_id, lease_epoch))
        try:
            result = (
                recovery.result
                if recovery.result is not None
                else await self._execute(handler, activity, lease_epoch)
            )
        except Exception as exc:
            if self._classify_failure(handler, activity, exc) == FailureDisposition.RECONCILE:
                self._activities.mark_reconciliation_required(
                    activity.activity_id,
                    actor_id=self._worker_id,
                    lease_epoch=lease_epoch,
                    error={
                        "reason": "uncertain_external_failure",
                        "error_type": type(exc).__name__,
                    },
                )
            raise
        finally:
            heartbeat.cancel()
            await asyncio.gather(heartbeat, return_exceptions=True)

        if crash_after_external_result:
            raise InjectedWorkerCrash(
                "injected after external completion before journal commit"
            )
        self._activities.complete(
            activity.activity_id,
            worker_id=self._worker_id,
            lease_epoch=lease_epoch,
            result_digest=result.result_digest,
        )
        return True

    async def _heartbeat(self, activity_id: str, lease_epoch: int) -> None:
        interval = max(0.1, self._lease_seconds / 3)
        while True:
            await asyncio.sleep(interval)
            try:
                self._activities.heartbeat(
                    activity_id,
                    worker_id=self._worker_id,
                    lease_epoch=lease_epoch,
                    lease_seconds=self._lease_seconds,
                )
            except ActivityConflictError:
                return

    @staticmethod
    async def _recover(handler: ActivityHandler, activity: ActivityRow) -> ActivityRecovery:
        method = getattr(handler, "recover", None)
        if method is not None:
            value = method(activity)
            if inspect.isawaitable(value):
                value = await value
            return cast(ActivityRecovery, value)
        legacy = getattr(handler, "find_durable_result", None)
        if legacy is None:
            return ActivityRecovery(RecoveryDisposition.AMBIGUOUS)
        result = legacy(activity)
        return ActivityRecovery(
            RecoveryDisposition.DURABLE_RESULT if result else RecoveryDisposition.NOT_STARTED,
            result,
        )

    @staticmethod
    async def _execute(
        handler: ActivityHandler, activity: ActivityRow, lease_epoch: int
    ) -> ActivityResult:
        method = handler.execute
        parameters = inspect.signature(method).parameters
        dynamic_method = cast(Any, method)
        if len(parameters) >= 2:
            if inspect.iscoroutinefunction(method):
                return cast(ActivityResult, await dynamic_method(activity, lease_epoch))
            return cast(
                ActivityResult,
                await asyncio.to_thread(dynamic_method, activity, lease_epoch),
            )
        if inspect.iscoroutinefunction(method):
            return cast(ActivityResult, await dynamic_method(activity))
        return cast(ActivityResult, await asyncio.to_thread(dynamic_method, activity))

    @staticmethod
    def _classify_failure(
        handler: ActivityHandler, activity: ActivityRow, error: Exception
    ) -> FailureDisposition:
        method = getattr(handler, "classify_failure", None)
        if method is not None:
            return cast(FailureDisposition, method(activity, error))
        return (
            FailureDisposition.RETRY
            if bool(getattr(handler, "safely_retryable", False))
            else FailureDisposition.RECONCILE
        )
