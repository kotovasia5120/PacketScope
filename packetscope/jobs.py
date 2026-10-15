"""A bounded analysis job manager.

The manager intentionally has one short-lived worker.  It provides a real
server-side lifecycle without introducing a queue service or unbounded
background threads.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass, field
import json
import queue
import threading
import time
import uuid
from typing import Any, Callable

from packetscope.analysis import analyze_packets
from packetscope.importers import import_bytes
from packetscope.models import Limits


@dataclass
class AnalysisJob:
    job_id: str
    name: str
    format_name: str
    payload: bytes
    analyze_raw: bool
    selected_direction: str = "both"
    flow_id: str | None = None
    created_at: float = field(default_factory=time.monotonic)
    status: str = "QUEUED"
    progress: int = 0
    result: dict[str, Any] | None = None
    error: str | None = None
    cancel_event: threading.Event = field(default_factory=threading.Event)


class AnalysisManager:
    _TERMINAL = frozenset({"COMPLETE", "FAILED", "CANCELLED"})

    def __init__(
        self,
        limits: Limits,
        *,
        max_queue: int = 4,
        retention_seconds: float = 120.0,
        importer: Callable[..., Any] | None = None,
        analyzer: Callable[..., dict[str, Any]] | None = None,
    ):
        if max_queue <= 0:
            raise ValueError("max_queue must be positive")
        self.limits = limits
        self.retention_seconds = retention_seconds
        self._importer = importer or import_bytes
        self._analyzer = analyzer or analyze_packets
        self._jobs: dict[str, AnalysisJob] = {}
        self._retained_payload_bytes = 0
        self._queue: queue.Queue[AnalysisJob] = queue.Queue(maxsize=max_queue)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._closed = False
        self._worker = threading.Thread(target=self._run, name="packetscope-analysis", daemon=True)
        self._worker.start()

    def submit(
        self,
        name: str,
        format_name: str,
        payload: bytes,
        analyze_raw: bool,
        *,
        selected_direction: str = "both",
        flow_id: str | None = None,
    ) -> AnalysisJob:
        job = AnalysisJob(uuid.uuid4().hex, name[:200], format_name, payload, analyze_raw, selected_direction, flow_id)
        with self._lock:
            if self._closed:
                raise RuntimeError("analysis manager is closed")
            self._cleanup_locked()
            if len(self._jobs) >= self.limits.max_retained_jobs:
                raise RuntimeError("job retention limit reached")
            payload_size = len(payload)
            if payload_size > self.limits.max_job_payload_bytes:
                raise RuntimeError("job payload exceeds retention limit")
            if self._retained_payload_bytes + payload_size > self.limits.max_job_payload_bytes:
                raise RuntimeError("job payload retention limit reached")
            # Enqueue and publish while holding the same lock.  This prevents
            # close() from stopping the worker between those two operations.
            try:
                self._queue.put_nowait(job)
            except queue.Full:
                raise RuntimeError("analysis queue is full") from None
            self._jobs[job.job_id] = job
            self._retained_payload_bytes += payload_size
        return job

    def get(self, job_id: str) -> dict[str, Any] | None:
        with self._lock:
            self._cleanup_locked()
            job = self._jobs.get(job_id)
            if job is None:
                return None
            return self._public(job)

    def cancel(self, job_id: str) -> bool:
        cancelled, _status = self.cancel_with_status(job_id)
        return cancelled

    def cancel_with_status(self, job_id: str) -> tuple[bool, str | None]:
        """Cancel a job and return ``(changed, current_status)`` atomically."""
        with self._lock:
            self._cleanup_locked()
            job = self._jobs.get(job_id)
            if job is None:
                return False, None
            if job.status in self._TERMINAL:
                return False, job.status
            job.cancel_event.set()
            if job.status == "QUEUED":
                self._mark_cancelled_locked(job)
            return True, job.status

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._closed = True
                self._stop.set()
                # A queued item will be skipped by the worker.  Active work
                # gets the same cancellation signal and is allowed to unwind.
                for job in self._jobs.values():
                    if job.status == "QUEUED":
                        job.cancel_event.set()
                        self._mark_cancelled_locked(job)
                    elif job.status in {"IMPORTING", "ANALYZING"}:
                        job.cancel_event.set()
        self._worker.join(timeout=max(1.0, self.limits.max_analysis_seconds + 1.0))

    def _run(self) -> None:
        while True:
            try:
                job = self._queue.get(timeout=0.25)
            except queue.Empty:
                if self._stop.is_set():
                    return
                continue
            try:
                with self._lock:
                    if job.cancel_event.is_set() or job.status == "CANCELLED":
                        continue
                    job.status = "IMPORTING"
                    job.progress = 5

                input_size = len(job.payload)
                try:
                    imported = self._importer(job.name, job.payload, job.format_name, self.limits)
                except Exception:
                    with self._lock:
                        self._release_payload_locked(job)
                    raise
                with self._lock:
                    self._release_payload_locked(job)
                    if job.cancel_event.is_set() or job.status in self._TERMINAL:
                        self._mark_cancelled_locked(job)
                        continue
                    job.status = "ANALYZING"
                    job.progress = max(job.progress, 10)

                def progress(value: int) -> None:
                    with self._lock:
                        if job.status != "ANALYZING" or job.cancel_event.is_set():
                            return
                        # The analyzer reports packet count; map it into the
                        # analysis half without trusting unbounded input.
                        job.progress = max(job.progress, min(95, 10 + min(85, int(value))))

                result = self._analyzer(
                    imported.packets,
                    limits=self.limits,
                    analyze_raw=job.analyze_raw,
                    selected_direction=job.selected_direction,
                    flow_id=job.flow_id,
                    cancel=job.cancel_event.is_set,
                    progress=progress,
                )
                result = dict(result)
                result["source"] = {
                    "name": job.name,
                    "format": imported.format,
                    "packet_count": len(imported.packets),
                    "byte_count": input_size,
                }
                result["warnings"] = _merge_warnings(result.get("warnings", []), imported.warnings)
                if len(json.dumps(result, sort_keys=True, separators=(",", ":"))) > self.limits.max_response_bytes:
                    raise ValueError("analysis result exceeds response limit")
                with self._lock:
                    # Cancellation and completion are one atomic decision.
                    # In particular, do not let a late cancel resurrect as a
                    # successful result.
                    if job.cancel_event.is_set() or result.get("status") == "CANCELLED":
                        self._mark_cancelled_locked(job)
                        continue
                    if job.status in self._TERMINAL:
                        continue
                    job.result = result
                    job.progress = 100
                    job.status = "COMPLETE"
            except Exception as exc:  # public error is bounded and payload-free
                with self._lock:
                    if job.status in self._TERMINAL:
                        continue
                    if job.cancel_event.is_set():
                        self._mark_cancelled_locked(job)
                    else:
                        job.error = _safe_error(exc)
                        job.status = "FAILED"
            finally:
                self._queue.task_done()

    def _mark_cancelled_locked(self, job: AnalysisJob) -> None:
        if job.status in {"COMPLETE", "FAILED"}:
            return
        job.status = "CANCELLED"
        job.progress = min(job.progress, 99)
        job.result = None
        job.error = None
        self._release_payload_locked(job)

    def _release_payload_locked(self, job: AnalysisJob) -> None:
        if not job.payload:
            return
        self._retained_payload_bytes -= len(job.payload)
        job.payload = b""

    def _cleanup_locked(self) -> None:
        now = time.monotonic()
        expired = [
            job_id
            for job_id, job in self._jobs.items()
            if job.status in self._TERMINAL and now - job.created_at > self.retention_seconds
        ]
        for job_id in expired:
            self._jobs.pop(job_id, None)

    @staticmethod
    def _public(job: AnalysisJob) -> dict[str, Any]:
        result: dict[str, Any] = {"job_id": job.job_id, "status": job.status, "progress": job.progress}
        if job.result is not None:
            result["result"] = copy.deepcopy(job.result)
        if job.error is not None:
            result["error"] = job.error
        return result


def _safe_error(_exc: Exception) -> str:
    """Return a stable error without echoing exception data or packet bytes."""
    return "analysis failed"


def _merge_warnings(analyzer: list[Any], importer: list[str]) -> list[dict[str, str]]:
    values: list[dict[str, str]] = []
    for warning in analyzer:
        if isinstance(warning, dict):
            values.append({"source": str(warning.get("source", "analyzer")), "message": str(warning.get("message", ""))})
        else:
            values.append({"source": "analyzer", "message": str(warning)})
    values.extend({"source": "importer", "message": str(warning)} for warning in importer)
    return sorted(values, key=lambda item: (item["source"], item["message"]))
