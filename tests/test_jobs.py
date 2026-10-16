import threading
import time
import unittest

from packetscope.importers.base import import_bytes as real_import_bytes
from packetscope.models import ImportResult, Packet
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

    def test_scope_selection_reaches_worker_analyzer(self):
        observed = {}
        started = threading.Event()

        def analyzer(packets, *, selected_direction, flow_id, **kwargs):
            observed.update(direction=selected_direction, flow_id=flow_id)
            started.set()
            return {"warnings": []}

        manager = self.make_manager(analyzer)
        try:
            job = manager.submit(
                "sample.bin", "bin", b"sample", False,
                selected_direction="reverse", flow_id="flow-1",
            )
            self.assertTrue(started.wait(1))
            self.assertEqual(wait_for(manager, job.job_id, {"COMPLETE"})["status"], "COMPLETE")
            self.assertEqual(observed, {"direction": "reverse", "flow_id": "flow-1"})
        finally:
            manager.close()

    def test_payload_retention_limit_rejects_and_recovers(self):
        importing = threading.Event()
        release = threading.Event()

        def importer(name, payload, format_name, limits):
            importing.set()
            release.wait(1)
            return ImportResult("bin", [Packet(0, payload)])

        manager = AnalysisManager(
            Limits(max_job_payload_bytes=10), max_queue=2,
            importer=importer, analyzer=lambda packets, **kwargs: {"warnings": []},
        )
        try:
            first = manager.submit("first.bin", "bin", b"12345", False)
            self.assertTrue(importing.wait(1))
            queued = manager.submit("queued.bin", "bin", b"12345", False)
            with self.assertRaisesRegex(RuntimeError, "payload retention limit"):
                manager.submit("rejected.bin", "bin", b"x", False)
            release.set()
            self.assertEqual(wait_for(manager, first.job_id, {"COMPLETE"})["status"], "COMPLETE")
            self.assertEqual(wait_for(manager, queued.job_id, {"COMPLETE"})["status"], "COMPLETE")
            self.assertEqual(manager._retained_payload_bytes, 0)
            recovered = manager.submit("recovered.bin", "bin", b"x", False)
            self.assertEqual(wait_for(manager, recovered.job_id, {"COMPLETE"})["status"], "COMPLETE")
        finally:
            release.set()
            manager.close()

    def test_cancel_during_import_releases_payload_after_import_unwinds(self):
        importing = threading.Event()
        release = threading.Event()

        def importer(name, payload, format_name, limits):
            importing.set()
            release.wait(1)
            return ImportResult("bin", [Packet(0, payload)])

        manager = AnalysisManager(
            Limits(max_job_payload_bytes=10), importer=importer,
            analyzer=lambda packets, **kwargs: {"warnings": []},
        )
        try:
            job = manager.submit("sample.bin", "bin", b"payload", False)
            self.assertTrue(importing.wait(1))
            self.assertTrue(manager.cancel(job.job_id))
            release.set()
            self.assertEqual(wait_for(manager, job.job_id, {"CANCELLED"})["status"], "CANCELLED")
            self.assertEqual(manager._retained_payload_bytes, 0)
        finally:
            release.set()
            manager.close()

    def test_oversized_completed_result_becomes_safe_failure(self):
        manager = AnalysisManager(
            Limits(max_response_bytes=64),
            analyzer=lambda packets, **kwargs: {"huge": "x" * 100, "warnings": []},
        )
        try:
            job = manager.submit("sample.bin", "bin", b"sample", False)
            result = wait_for(manager, job.job_id, {"FAILED"})
            self.assertEqual(result["error"], "analysis failed")
            self.assertEqual(manager._retained_payload_bytes, 0)
        finally:
            manager.close()

    def test_active_job_is_not_expired_by_creation_age(self):
        started = threading.Event()
        completed = threading.Event()
        release = threading.Event()

        def analyzer(packets, *, cancel, **kwargs):
            started.set()
            release.wait(1)
            completed.set()
            return {"warnings": []}

        manager = self.make_manager(analyzer, retention_seconds=0.01)
        try:
            job = manager.submit("active.bin", "bin", b"active", False)
            self.assertTrue(started.wait(1))
            with manager._lock:
                manager._jobs[job.job_id].created_at -= 100
            self.assertIn(manager.get(job.job_id)["status"], {"ANALYZING", "COMPLETE"})
            release.set()
            self.assertTrue(completed.wait(1))
            with manager._lock:
                self.assertEqual(manager._jobs[job.job_id].status, "COMPLETE")
        finally:
            release.set()
            manager.close()

    def test_controlled_experiment_imports_two_sources_and_keeps_provenance(self):
        manager = self.make_manager(lambda packets, **kwargs: {"warnings": []})
        try:
            job = manager.submit_controlled_experiment(
                "baseline.bin", "bin", b"\xaa\x01\x10",
                "changed.bin", "bin", b"\xaa\x01\x20",
                False,
                baseline_direction="both",
                changed_direction="both",
                change_label="setting changed",
            )
            result = wait_for(manager, job.job_id, {"COMPLETE"})
            report = result["result"]
            self.assertEqual(report["change_label"], "setting changed")
            self.assertEqual(report["baseline"]["name"], "baseline.bin")
            self.assertEqual(report["changed"]["byte_count"], 3)
            self.assertEqual(report["selection"]["independent_scopes"], True)
            self.assertEqual(len(report["baseline"]["raw_sha256"]), 64)
            self.assertEqual(len(report["changed"]["raw_sha256"]), 64)
            self.assertEqual(manager._retained_payload_bytes, 0)
        finally:
            manager.close()

    def test_controlled_experiment_cancellation_releases_both_payloads(self):
        started = threading.Event()

        def experimenter(packets, changed, *, cancel, **kwargs):
            started.set()
            while not cancel():
                time.sleep(0.002)
            return {"status": "CANCELLED", "warnings": []}

        manager = AnalysisManager(
            Limits(max_job_payload_bytes=32),
            experimenter=experimenter,
        )
        try:
            job = manager.submit_controlled_experiment(
                "baseline.bin", "bin", b"123456",
                "changed.bin", "bin", b"abcdef",
                False,
            )
            self.assertTrue(started.wait(1))
            self.assertTrue(manager.cancel(job.job_id))
            self.assertEqual(wait_for(manager, job.job_id, {"CANCELLED"})["status"], "CANCELLED")
            self.assertEqual(manager._retained_payload_bytes, 0)
        finally:
            manager.close()


if __name__ == "__main__":
    unittest.main()
