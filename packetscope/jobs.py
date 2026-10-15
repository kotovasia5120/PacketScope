"""A bounded, local-only analysis job manager.

The manager intentionally has one short-lived worker.  It provides a real
server-side lifecycle without introducing a queue service or unbounded
background threads.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import queue
import threading
import time
import uuid
from typing import Any

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
    created_at: float = field(default_factory=time.monotonic)
    status: str = "QUEUED"
    progress: int = 0
    result: dict[str, Any] | None = None
    error: str | None = None
    cancel_event: threading.Event = field(default_factory=threading.Event)


class AnalysisManager:
    def __init__(self, limits: Limits, *, max_queue: int = 4, retention_seconds: float = 120.0):
        self.limits = limits
        self.retention_seconds = retention_seconds
        self._jobs: dict[str, AnalysisJob] = {}
        self._queue: queue.Queue[AnalysisJob | None] = queue.Queue(maxsize=max_queue)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._worker = threading.Thread(target=self._run, name="packetscope-analysis", daemon=True)
        self._worker.start()

    def submit(self, name: str, format_name: str, payload: bytes, analyze_raw: bool) -> AnalysisJob:
        job = AnalysisJob(uuid.uuid4().hex, name[:200], format_name, payload, analyze_raw)
        with self._lock:
            self._cleanup_locked()
            self._jobs[job.job_id] = job
        try:
            self._queue.put_nowait(job)
        except queue.Full:
            with self._lock:
                self._jobs.pop(job.job_id, None)
            raise RuntimeError("analysis queue is full")
        return job

    def get(self, job_id: str) -> dict[str, Any] | None:
        with self._lock:
            self._cleanup_locked()
            job = self._jobs.get(job_id)
            if job is None:
                return None
            return self._public(job)

    def cancel(self, job_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None or job.status in {"COMPLETE", "FAILED", "CANCELLED"}:
                return False
            job.cancel_event.set()
            if job.status == "QUEUED":
                job.status = "CANCELLED"
            return True

    def close(self) -> None:
        self._stop.set()
        try:
            self._queue.put_nowait(None)
        except queue.Full:
            pass
        self._worker.join(timeout=max(1.0, self.limits.max_analysis_seconds + 1.0))

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                job = self._queue.get(timeout=0.25)
            except queue.Empty:
                continue
            if job is None:
                return
            with self._lock:
                if job.cancel_event.is_set() or job.status == "CANCELLED":
                    self._queue.task_done()
                    continue
                job.status = "IMPORTING"
                job.progress = 5
            try:
                imported = import_bytes(job.name, job.payload, job.format_name, self.limits)
                if job.cancel_event.is_set():
                    self._finish_cancelled(job)
                    continue
                with self._lock:
                    job.status = "ANALYZING"
                    job.progress = 10

                def progress(value: int) -> None:
                    with self._lock:
                        # The analyzer reports packet count; map it into the
                        # analysis half without trusting unbounded input.
                        job.progress = min(95, 10 + min(85, int(value)))

                result = analyze_packets(imported.packets, limits=self.limits, analyze_raw=job.analyze_raw,
                                         cancel=job.cancel_event.is_set, progress=progress)
                if job.cancel_event.is_set() or result.get("status") == "CANCELLED":
                    self._finish_cancelled(job)
                    continue
                result["source"] = {"name": job.name, "format": imported.format,
                                     "packet_count": len(imported.packets), "byte_count": len(job.payload)}
                result["warnings"] = _merge_warnings(result.get("warnings", []), imported.warnings)
                with self._lock:
                    job.result = result
                    job.progress = 100
                    job.status = "COMPLETE"
            except Exception as exc:  # public error is bounded and payload-free
                with self._lock:
                    job.error = str(exc)[:300]
                    job.status = "FAILED"
            finally:
                self._queue.task_done()

    def _finish_cancelled(self, job: AnalysisJob) -> None:
        with self._lock:
            job.status = "CANCELLED"
            job.progress = min(job.progress, 99)

    def _cleanup_locked(self) -> None:
        now = time.monotonic()
        expired = [job_id for job_id, job in self._jobs.items()
                   if job.status in {"COMPLETE", "FAILED", "CANCELLED"}
                   and now - job.created_at > self.retention_seconds]
        for job_id in expired:
            self._jobs.pop(job_id, None)

    @staticmethod
    def _public(job: AnalysisJob) -> dict[str, Any]:
        result: dict[str, Any] = {"job_id": job.job_id, "status": job.status, "progress": job.progress}
        if job.result is not None:
            result["result"] = job.result
        if job.error is not None:
            result["error"] = job.error
        return result


def _merge_warnings(analyzer: list[Any], importer: list[str]) -> list[dict[str, str]]:
    values: list[dict[str, str]] = []
    for warning in analyzer:
        if isinstance(warning, dict):
            values.append({"source": str(warning.get("source", "analyzer")), "message": str(warning.get("message", ""))})
        else:
            values.append({"source": "analyzer", "message": str(warning)})
    values.extend({"source": "importer", "message": str(warning)} for warning in importer)
    return sorted(values, key=lambda item: (item["source"], item["message"]))
