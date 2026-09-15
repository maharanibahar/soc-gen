import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "stage2_triage",
    REPO_ROOT / "stage2-path2-triage-pipeline-v2.py",
)
STAGE2 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STAGE2)


def example_event():
    return {
        "ip": "10.21.224.123",
        "timestamp": "2026-05-05T19:18:07Z",
        "source_type": "web_server",
        "details": {
            "method": "GET",
            "path": "/?instawp-database-manager=/../../../%2e%2fmigrate%2ftemplates%2fdebug%2fdb-table&table_name=wp_users--%20-",
            "status": 200,
            "forwarded_for": "157.85.96.175, 172.68.189.212",
        },
    }


class SignatureInspectionTests(unittest.TestCase):
    def test_example_detects_traversal_sql_comment_and_sensitive_target(self):
        result = STAGE2.run_signature_inspection(example_event())
        rule_ids = set(result["signature_reasons"])

        self.assertTrue(result["signature_custom_http"])
        self.assertIn("HTTP-PATH-001", rule_ids)
        self.assertIn("HTTP-SQLI-002", rule_ids)
        self.assertIn("HTTP-WORDPRESS-001", rule_ids)
        self.assertEqual(result["http_normalization"]["route"], "/")
        self.assertEqual(result["effective_client_ip"], "10.21.224.123")

    def test_normal_request_does_not_match_custom_attack_rules(self):
        event = {
            "ip": "192.0.2.10",
            "source_type": "web_server",
            "details": {
                "method": "GET",
                "path": "/products?category=books&page=2",
                "status": 200,
            },
        }

        result = STAGE2.run_signature_inspection(event)

        self.assertFalse(result["signature_custom_http"])
        self.assertEqual(result["signature_reasons"], [])

    def test_forwarded_client_requires_trusted_proxy_chain(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trusted-proxies.json"
            path.write_text(json.dumps({
                "version": "test-1",
                "networks": ["10.0.0.0/8", "172.64.0.0/13"],
            }))

            event = example_event()
            result = STAGE2.run_signature_inspection(event, trusted_proxies_path=path)

        self.assertEqual(event["effective_client_ip"], "157.85.96.175")
        self.assertEqual(result["client_ip_source"], "trusted_forwarded_chain")
        self.assertEqual(result["trusted_proxy_config_version"], "test-1")

    def test_external_threat_intel_snapshot_records_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "threat-intel.json"
            path.write_text(json.dumps({
                "feed": {"name": "test-feed", "version": "2026-09-15"},
                "indicators": {
                    "ips": [{
                        "id": "IOC-7",
                        "value": "10.21.224.123",
                        "severity": "high",
                        "confidence": 0.97,
                    }],
                    "domains": [],
                    "urls": [],
                    "file_names": [],
                    "file_hashes": [],
                    "users": [],
                },
            }))

            result = STAGE2.run_signature_inspection(example_event(), threat_intel_path=path)

        hit = next(hit for hit in result["detection_hits"] if hit["rule_id"] == "IOC-7")
        self.assertTrue(result["signature_threat_intel"])
        self.assertEqual(hit["rule_source"], "test-feed")
        self.assertEqual(hit["rule_version"], "2026-09-15")

    def test_upstream_crs_ids_are_not_confused_with_custom_rules(self):
        event = example_event()
        event["details"]["owasp_crs_rule_ids"] = ["930100", "942100"]
        event["details"]["owasp_crs_version"] = "4.0.0"

        result = STAGE2.run_signature_inspection(event)
        crs_hits = [
            hit for hit in result["detection_hits"]
            if hit["rule_source"] == "owasp-crs-upstream"
        ]

        self.assertTrue(result["signature_upstream_owasp_crs"])
        self.assertEqual([hit["rule_id"] for hit in crs_hits], ["930100", "942100"])
        self.assertTrue(all(hit["rule_version"] == "4.0.0" for hit in crs_hits))

    def test_offline_crs_replay_becomes_detector_evidence(self):
        event = example_event()
        event["crs_replay"] = {
            "engine": "coraza",
            "engine_version": "3.7.0",
            "crs_version": "4.25.0",
            "coverage": {"level": "partial"},
            "matched_rules": [{
                "id": 930100,
                "message": "Path Traversal Attack",
                "severity": "critical",
                "tags": ["attack-lfi", "OWASP_CRS"],
                "is_attack": True,
                "matched_variables": [{
                    "variable": "ARGS",
                    "key": "instawp-database-manager",
                    "value": "/../../../migrate",
                }],
            }],
        }

        result = STAGE2.run_signature_inspection(event)
        hit = next(
            hit for hit in result["detection_hits"]
            if hit["rule_source"] == "owasp-crs-offline-coraza"
        )

        self.assertTrue(result["signature_offline_owasp_crs"])
        self.assertEqual(hit["rule_id"], "930100")
        self.assertEqual(hit["matched_field"], "ARGS:instawp-database-manager")
        self.assertEqual(hit["coverage"], {"level": "partial"})


if __name__ == "__main__":
    unittest.main()
