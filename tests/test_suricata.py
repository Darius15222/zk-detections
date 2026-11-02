"""R-04: run pipelines/suricata.conf in a real Logstash and check the ECS output; validate the Suricata rules.
Stdlib only (unittest). Needs Docker. Images pinned by digest.
Run: python3 tests/test_suricata.py -v
"""
import json
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "tests" / "samples"
LOGSTASH = "docker.elastic.co/logstash/logstash:9.5.0@sha256:b08a2b7767573295e6a53b72214ca42522c4c7a8edbbc7e0af8ef470dcf2f2d3"
SURICATA = "jasonish/suricata:8.0.8@sha256:d5a3a1785299ab40918d465e54fedf8e3afeeedba76bb64b0cc74dbc20bda2c3"


def run_logstash(lines: str) -> list[dict]:
    cmd = [
        "docker", "run", "--rm", "-i",
        "-v", f"{ROOT / 'pipelines' / 'suricata.conf'}:/pipe/10-suricata.conf:ro",
        "-v", f"{ROOT / 'tests' / 'harness.conf'}:/pipe/00-harness.conf:ro",
        LOGSTASH, "logstash", "-f", "/pipe", "--log.level=error", "-w", "1",
    ]
    out = subprocess.run(cmd, input=lines, capture_output=True, text=True, timeout=600, check=True).stdout
    return [json.loads(line) for line in out.splitlines() if line.startswith("{")]


class SuricataPipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # one Logstash start for all samples (startup dominates the run time)
        names = ["suricata_alert.json", "suricata_http.json", "suricata_stats.json", "suricata_invalid.txt"]
        cls.events = run_logstash("".join((SAMPLES / n).read_text() for n in names))

    def by_type(self, t):
        return [e for e in self.events if e.get("suricata", {}).get("event_type") == t]

    def test_alert_maps_to_ecs(self):
        (ev,) = self.by_type("alert")
        self.assertEqual(ev["source"], {"ip": "10.42.0.9", "port": 51514})
        self.assertEqual(ev["destination"], {"ip": "10.42.0.20", "port": 8080})
        self.assertEqual(ev["network"]["transport"], "tcp")
        self.assertEqual(ev["event"]["kind"], "alert")
        self.assertEqual(sorted(ev["event"]["category"]), ["intrusion_detection", "network"])
        self.assertEqual(ev["rule"]["id"], 9000001)
        self.assertEqual(ev["rule"]["name"], "ZK-LAB login burst")
        self.assertEqual(ev["url"]["original"], "/login/password")
        self.assertTrue(ev["@timestamp"].startswith("2026-11-02T10:15:30.123"))
        self.assertIn("event_type", ev["event"]["original"])

    def test_http_maps_to_ecs(self):
        (ev,) = self.by_type("http")
        self.assertEqual(ev["event"]["kind"], "event")
        self.assertEqual(ev["http"]["request"]["method"], "POST")
        self.assertEqual(ev["http"]["response"]["status_code"], 401)
        self.assertEqual(ev["url"]["domain"], "auth.zk.local")
        self.assertEqual(ev["user_agent"]["original"], "python-requests/2.32")

    def test_stats_are_dropped(self):
        self.assertEqual(self.by_type("stats"), [])

    def test_invalid_json_is_tagged_and_unmapped(self):
        (ev,) = [e for e in self.events if "_jsonparsefailure" in e.get("tags", [])]
        self.assertNotIn("source", ev)
        # Logstash (ECS mode) adds event.original by itself; nothing from the mapping may appear
        self.assertNotIn("kind", ev.get("event", {}))
        self.assertNotIn("module", ev.get("event", {}))

    def test_nothing_else_comes_out(self):
        self.assertEqual(len(self.events), 3)


class SuricataRules(unittest.TestCase):
    def test_rules_load(self):
        cmd = [
            "docker", "run", "--rm", "-v", f"{ROOT / 'rules' / 'suricata'}:/rules:ro",
            SURICATA, "-T", "-S", "/rules/local.rules", "-l", "/tmp",
        ]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
