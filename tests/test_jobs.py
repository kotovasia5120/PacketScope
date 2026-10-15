import threading
import time
import unittest

from packetscope.importers.base import import_bytes as real_import_bytes
from packetscope.jobs import AnalysisManager
from packetscope.models import Limits


def wait_for(manager: AnalysisManager, job_id: str, statuses: set[str], timeout: float = 2.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = manager.get(job_id)
        if value and value["status"] in statuses:
            return value
        time.sleep(0.005)
    raise AssertionError(f"job did not reach {statuses}")


class AnalysisManagerTests(unittest.TestCase):
    def make_manager(self, analyzer, *, max_queue=4, retention_seconds=120.0):
        return AnalysisManager(
            Limits(max_analysis_seconds=1.0),
            max_queue=max_queue,
            retention_seconds=retention_seconds,
            importer=real_import_bytes,
            analyzer=analyzer,
        )

    def test_cancel_before_execution(self):
        started = threading.Event()
        release = threading.Event()

        def analyzer(packets, **kwargs):
            started.set()
            release.wait(2)
            return {"analysis": {"status": "ok"}, "warnings": []}

        manager = self.make_manager(analyzer, max_queue=2)
        try:
            first = manager.submit("first.bin", "bin", b"first", False)
            self.assertTrue(started.wait(1))
            second = manager.submit("second.bin", "bin", b"second", False)
            self.assertTrue(manager.cancel(second.job_id))
            self.assertEqual(manager.get(second.job_id)["status"], "CANCELLED")
            release.set()
            self.assertEqual(wait_for(manager, first.job_id, {"COMPLETE"})["status"], "COMPLETE")
            self.assertEqual(manager.get(second.job_id)["status"], "CANCELLED")
        finally:
            release.set()
            manager.close()

    def test_cancel_during_analysis_is_terminal(self):
        started = threading.Event()
        cancelled = threading.Event()

        def analyzer(packets, *, cancel, **kwargs):
            started.set()
            while not cancel():
                time.sleep(0.002)
            cancelled.set()
            return {"status": "CANCELLED", "warnings": []}

        manager = self.make_manager(analyzer)
        try:
            job = manager.submit("sample.bin", "bin", b"sample", False)
            self.assertTrue(started.wait(1))
            self.assertTrue(manager.cancel(job.job_id))
            result = wait_for(manager, job.job_id, {"CANCELLED"})
            self.assertTrue(cancelled.is_set())
            self.assertNotIn("result", result)
            self.assertFalse(manager.cancel(job.job_id))
        finally:
            manager.close()

    def test_queue_overflow_does_not_publish_rejected_job(self):
        started = threading.Event()
        release = threading.Event()

        def analyzer(packets, **kwargs):
            started.set()
            release.wait(2)
            return {"warnings": []}

        manager = self.make_manager(analyzer, max_queue=1)
        try:
            active = manager.submit("active.bin", "bin", b"active", False)
            self.assertTrue(started.wait(1))
            queued = manager.submit("queued.bin", "bin", b"queued", False)
            with self.assertRaisesRegex(RuntimeError, "queue is full"):
                manager.submit("rejected.bin", "bin", b"rejected", False)
            self.assertIsNone(manager.get("rejected"))
            release.set()
            self.assertEqual(wait_for(manager, active.job_id, {"COMPLETE"})["status"], "COMPLETE")
            self.assertEqual(wait_for(manager, queued.job_id, {"COMPLETE"})["status"], "COMPLETE")
        finally:
            release.set()
            manager.close()

    def test_worker_exception_is_failed_without_exception_data(self):
        def analyzer(packets, **kwargs):
            raise RuntimeError("secret packet payload")

        manager = self.make_manager(analyzer)
        try:
            job = manager.submit("sample.bin", "bin", b"sample", False)
            result = wait_for(manager, job.job_id, {"FAILED"})
            self.assertEqual(result["error"], "analysis failed")
            self.assertNotIn("secret", result["error"])
        finally:
            manager.close()

    def test_terminal_reads_are_idempotent_and_snapshot_results(self):
        def analyzer(packets, **kwargs):
            return {"nested": {"value": 1}, "warnings": []}

        manager = self.make_manager(analyzer)
        try:
            job = manager.submit("sample.bin", "bin", b"sample", False)
            first = wait_for(manager, job.job_id, {"COMPLETE"})
            first["result"]["nested"]["value"] = 99
            second = manager.get(job.job_id)
            self.assertEqual(second["status"], "COMPLETE")
            self.assertEqual(second["result"]["nested"]["value"], 1)
            self.assertEqual(second["progress"], 100)
        finally:
            manager.close()

    def test_terminal_jobs_are_cleaned_up(self):
        manager = self.make_manager(lambda packets, **kwargs: {"warnings": []}, retention_seconds=120)
        try:
            job = manager.submit("sample.bin", "bin", b"sample", False)
            wait_for(manager, job.job_id, {"COMPLETE"})
            with manager._lock:
                manager._jobs[job.job_id].created_at -= 121
            self.assertIsNone(manager.get(job.job_id))
        finally:
            manager.close()

    def test_close_cancels_queued_work_and_stops_worker(self):
        started = threading.Event()
        release = threading.Event()

        def analyzer(packets, *, cancel, **kwargs):
            started.set()
            while not cancel():
                time.sleep(0.002)
            release.set()
            return {"status": "CANCELLED", "warnings": []}

        manager = self.make_manager(analyzer, max_queue=2)
        active = manager.submit("active.bin", "bin", b"active", False)
        queued = manager.submit("queued.bin", "bin", b"queued", False)
        self.assertTrue(started.wait(1))
        manager.close()
        self.assertFalse(manager._worker.is_alive())
        self.assertEqual(manager.get(active.job_id)["status"], "CANCELLED")
        self.assertEqual(manager.get(queued.job_id)["status"], "CANCELLED")
        with self.assertRaisesRegex(RuntimeError, "manager is closed"):
            manager.submit("later.bin", "bin", b"later", False)


if __name__ == "__main__":
    unittest.main()
