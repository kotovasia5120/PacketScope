"""A bounded analysis job manager.

The manager intentionally has one short-lived worker.  It provides a real
server-side lifecycle without introducing a queue service or unbounded
background threads.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass, field
import hashlib
import json
import queue
import threading
import time
import uuid
from typing import Any, Callable

from packetscope.analysis import analyze_packets
from packetscope.experiments import compare_controlled_change
from packetscope.flows import group_flows, normalize_direction, select_flow_packets
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


@dataclass
class ControlledExperimentJob:
    job_id: str
    baseline_name: str
    baseline_format: str
    baseline_payload: bytes
    changed_name: str
    changed_format: str
    changed_payload: bytes
    analyze_raw: bool
    baseline_direction: str = "both"
    changed_direction: str = "both"
    baseline_flow_id: str | None = None
    changed_flow_id: str | None = None
    change_label: str = "controlled change"
    baseline_raw_sha256: str = ""
    changed_raw_sha256: str = ""
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
        experimenter: Callable[..., dict[str, Any]] | None = None,
    ):
        if max_queue <= 0:
            raise ValueError("max_queue must be positive")
        self.limits = limits
        self.retention_seconds = retention_seconds
        self._importer = importer or import_bytes
        self._analyzer = analyzer or analyze_packets
        self._experimenter = experimenter or compare_controlled_change
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

    def submit_controlled_experiment(
        self,
        baseline_name: str,
        baseline_format: str,
        baseline_payload: bytes,
        changed_name: str,
        changed_format: str,
        changed_payload: bytes,
        analyze_raw: bool,
        *,
        baseline_direction: str = "both",
        changed_direction: str = "both",
        baseline_flow_id: str | None = None,
        changed_flow_id: str | None = None,
        change_label: str = "controlled change",
    ) -> ControlledExperimentJob:
        baseline_direction = normalize_direction(baseline_direction)
        changed_direction = normalize_direction(changed_direction)
        baseline_name = baseline_name[:200]
        changed_name = changed_name[:200]
        baseline_payload = bytes(baseline_payload)
        changed_payload = bytes(changed_payload)
        job = ControlledExperimentJob(
            uuid.uuid4().hex,
            baseline_name,
            baseline_format,
            baseline_payload,
            changed_name,
            changed_format,
            changed_payload,
            analyze_raw,
            baseline_direction,
            changed_direction,
            baseline_flow_id,
            changed_flow_id,
            str(change_label)[:120] or "controlled change",
            hashlib.sha256(baseline_payload).hexdigest(),
            hashlib.sha256(changed_payload).hexdigest(),
        )
        with self._lock:
            if self._closed:
                raise RuntimeError("analysis manager is closed")
            self._cleanup_locked()
            if len(self._jobs) >= self.limits.max_retained_jobs:
                raise RuntimeError("job retention limit reached")
            payload_size = len(baseline_payload) + len(changed_payload)
            if payload_size > self.limits.max_job_payload_bytes:
                raise RuntimeError("job payload exceeds retention limit")
            if self._retained_payload_bytes + payload_size > self.limits.max_job_payload_bytes:
                raise RuntimeError("job payload retention limit reached")
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
                if isinstance(job, ControlledExperimentJob):
                    self._run_experiment(job)
                else:
                    self._run_analysis(job)
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

    def _run_analysis(self, job: AnalysisJob) -> None:
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
                return
            job.status = "ANALYZING"
            job.progress = max(job.progress, 10)

        def progress(value: int) -> None:
            with self._lock:
                if job.status != "ANALYZING" or job.cancel_event.is_set():
                    return
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
        self._publish_result(job, result)

    def _run_experiment(self, job: ControlledExperimentJob) -> None:
        baseline_size = len(job.baseline_payload)
        changed_size = len(job.changed_payload)
        try:
            baseline = self._importer(job.baseline_name, job.baseline_payload, job.baseline_format, self.limits)
        except Exception:
            with self._lock:
                self._release_payload_locked(job)
            raise
        with self._lock:
            self._release_experiment_payload_locked(job, baseline=True)
        if job.cancel_event.is_set():
            with self._lock:
                self._mark_cancelled_locked(job)
            return
        with self._lock:
            job.progress = max(job.progress, 22)
        try:
            changed = self._importer(job.changed_name, job.changed_payload, job.changed_format, self.limits)
        except Exception:
            with self._lock:
                self._release_payload_locked(job)
            raise
        with self._lock:
            self._release_experiment_payload_locked(job, baseline=False)
        if job.cancel_event.is_set():
            with self._lock:
                self._mark_cancelled_locked(job)
            return

        baseline_packets = _select_packets(baseline.packets, job.baseline_direction, job.baseline_flow_id, self.limits)
        changed_packets = _select_packets(changed.packets, job.changed_direction, job.changed_flow_id, self.limits)
        with self._lock:
            job.status = "ANALYZING"
            job.progress = max(job.progress, 35)

        def progress(value: int) -> None:
            with self._lock:
                if job.status != "ANALYZING" or job.cancel_event.is_set():
                    return
                job.progress = max(job.progress, min(95, int(value)))

        result = dict(self._experimenter(
            baseline_packets,
            changed_packets,
            limits=self.limits,
            analyze_raw=job.analyze_raw,
            change_label=job.change_label,
            cancel=job.cancel_event.is_set,
            progress=progress,
        ))
        result["baseline"].update({
            "name": job.baseline_name,
            "format": baseline.format,
            "byte_count": baseline_size,
            "raw_sha256": job.baseline_raw_sha256,
        })
        result["changed"].update({
            "name": job.changed_name,
            "format": changed.format,
            "byte_count": changed_size,
            "raw_sha256": job.changed_raw_sha256,
        })
        result["selection"] = {
            "baseline_flow_id": job.baseline_flow_id,
            "changed_flow_id": job.changed_flow_id,
            "baseline_direction": job.baseline_direction,
            "changed_direction": job.changed_direction,
            "independent_scopes": True,
        }
        result["provenance"] = {
            "operation": "controlled_experiment",
            "tool": {"name": "PacketScope", "version": "0.2.0"},
            "coordinate_system": result.get("coordinate_system"),
            "analyze_raw": job.analyze_raw,
            "baseline_raw_sha256": job.baseline_raw_sha256,
            "changed_raw_sha256": job.changed_raw_sha256,
        }
        result["warnings"] = _merge_warnings(
            [],
            [{"source": "baseline_importer", "message": warning} for warning in baseline.warnings]
            + [{"source": "changed_importer", "message": warning} for warning in changed.warnings],
        )
        self._publish_result(job, result)

    def _publish_result(self, job: AnalysisJob | ControlledExperimentJob, result: dict[str, Any]) -> None:
        if len(json.dumps(result, sort_keys=True, separators=(",", ":"))) > self.limits.max_response_bytes:
            raise ValueError("analysis result exceeds response limit")
        with self._lock:
            if job.cancel_event.is_set() or result.get("status") == "CANCELLED":
                self._mark_cancelled_locked(job)
                return
            if job.status in self._TERMINAL:
                return
            job.result = result
            job.progress = 100
            job.status = "COMPLETE"

    def _mark_cancelled_locked(self, job: AnalysisJob) -> None:
        if job.status in {"COMPLETE", "FAILED"}:
            return
        job.status = "CANCELLED"
        job.progress = min(job.progress, 99)
        job.result = None
        job.error = None
        self._release_payload_locked(job)

    def _release_payload_locked(self, job: AnalysisJob | ControlledExperimentJob) -> None:
        if isinstance(job, ControlledExperimentJob):
            self._release_experiment_payload_locked(job, baseline=True)
            self._release_experiment_payload_locked(job, baseline=False)
            return
        if not job.payload:
            return
        self._retained_payload_bytes -= len(job.payload)
        job.payload = b""

    def _release_experiment_payload_locked(self, job: ControlledExperimentJob, *, baseline: bool) -> None:
        attribute = "baseline_payload" if baseline else "changed_payload"
        payload = getattr(job, attribute)
        if payload:
            self._retained_payload_bytes -= len(payload)
            setattr(job, attribute, b"")

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


def _select_packets(packets: list[Any], direction: str, flow_id: str | None, limits: Limits) -> list[Any]:
    """Apply one independently validated experiment scope without trusting client bytes."""
    if flow_id is not None:
        flows = group_flows(packets, limits=limits)
        if not any(flow.flow_id == flow_id for flow in flows):
            raise ValueError("experiment flow selection is unavailable")
    return select_flow_packets(
        packets,
        selected_direction=direction,
        flow_id=flow_id,
        limits=limits,
    )
