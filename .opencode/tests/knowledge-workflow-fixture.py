"""Exercise the bridge against a fixed native-index contract, without a live KB."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

path = Path(__file__).resolve().parents[1] / "lib/knowledge-workflow.py"
spec = importlib.util.spec_from_file_location("knowledge_bridge", path)
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


class NativeFixture:
    def __init__(self):
        self.errors = []
        self.quality = {"warnings": ["来源已变化；旧评估不采用。"], "summary": {"mechanisms": 1}}
        self.docs = [{"uid": "mechanism:MECH-FIXTURE", "id": "MECH-FIXTURE", "kind": "mechanism",
                      "title": "测试安全条件", "summary": "必须核实当前代码", "path": "card.yaml",
                      "payload": {"security_invariant": "测试条件", "counterexamples": ["安全反例"],
                                  "evidence_status": "stale", "cross_project_status": "not_evaluated", "detectors": []},
                      "quality": {"generalization": "not_evaluated"}, "curation": {"status": "stale"}}]

    def get(self, uid):
        return next((doc for doc in self.docs if doc["uid"] == uid), None)

    def resolve(self, identifier):
        return next((doc for doc in self.docs if doc["id"] == identifier), None)

    def related(self, uid):
        return [{"uid": "case:one"}, {"uid": "case:two"}]

    def search(self, **options):
        self.options = options
        return {"total": 1, "offset": options["offset"], "limit": options["limit"],
                "results": [{"uid": self.docs[0]["uid"], "score": 1, "snippet": "安全条件"}]}

    def stats(self):
        return {"documents": len(self.docs)}


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        (self.root / "card.yaml").write_text("fixture: true\n", encoding="utf-8")
        self.index = NativeFixture()

    def test_quality_and_counterexamples_are_not_promoted(self):
        result = bridge.query_index(self.root, self.index, {"command": "show", "id": "MECH-FIXTURE", "offset": 1, "limit": 1})
        self.assertEqual(result["status"], "PARTIAL")
        self.assertFalse(result["automatic_vulnerability_verdict"])
        document = result["document"]
        self.assertEqual(document["payload"]["counterexamples"], ["安全反例"])
        self.assertEqual(document["mechanism_status"]["evidence_status"], "stale")
        self.assertEqual(document["curation"]["status"], "stale")
        self.assertEqual(document["detectors"], [])
        self.assertEqual(document["related"], [{"uid": "case:two"}])
        self.assertEqual(document["related_total"], 2)
        self.assertEqual(document["source"]["sha256"], hashlib.sha256(b"fixture: true\n").hexdigest())

    def test_mechanism_first_and_filter_passthrough(self):
        bridge.query_index(self.root, self.index, {"command": "search", "query": "边界", "filters": {"weakness": ["CWE-89"]}})
        self.assertEqual(self.index.options["filters"], {"kind": ["mechanism"], "weakness": ["CWE-89"]})

    def test_missing_and_partial_indices_are_explicit(self):
        self.assertEqual(bridge.query_index(self.root, self.index, {"command": "show", "id": "absent"})["status"], "NOT_FOUND")
        self.index.docs = []
        self.assertEqual(bridge.query_index(self.root, self.index, {"command": "status"})["status"], "UNAVAILABLE")

    def test_source_cannot_escape_knowledge_root(self):
        with self.assertRaises(ValueError):
            bridge.checked_path(self.root, "..")


if __name__ == "__main__":
    unittest.main()
