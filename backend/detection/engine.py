"""Detection orchestrator. Takes each batch of flushed flows and runs the
full pipeline: window -> rules + baseline -> severity -> suppression ->
threat score -> persist. This is what makes detection live."""
import json
import time
from collections import defaultdict
from pathlib import Path

from backend.config import BASE_DIR
from backend.storage import queries as q
from backend.detection.window import SlidingWindow
from backend.detection import rules
from backend.detection.baseline import BaselineEngine
from backend.detection.severity import score_finding
from backend.detection.suppression import Suppressor, detect_gateway
from backend.detection.threat_score import ThreatScorer

THRESHOLDS_FILE = BASE_DIR / "backend" / "detection" / "thresholds.json"


def load_thresholds():
    try:
        data = json.loads(Path(THRESHOLDS_FILE).read_text())
        return data.get("thresholds", {})
    except (OSError, ValueError):
        return {}


class DetectionEngine:
    def __init__(self, conn):
        self.conn = conn
        self.window = SlidingWindow()
        self.baseline = BaselineEngine()
        self.thresholds = load_thresholds()
        gw = detect_gateway()
        self.suppressor = Suppressor(gateway_ip=gw)
        self.threat = ThreatScorer()
        self._minute_acc = defaultdict(lambda: {"bytes": 0, "conns": 0})
        self._last_minute = None
        print("detection engine ready (gateway allowlisted: " + str(gw) + ")")

    def process(self, flow_rows, dns_rows=None):
        """Run detection on one batch of flushed flows. Returns new alerts."""
        self.window.add_flows(flow_rows)

        # signature rules over the short window
        short = self.window.get("short")
        findings = []
        for rule_fn in rules.ALL_RULES:
            findings.extend(rule_fn(short, self.thresholds))
        if dns_rows:
            findings.extend(rules.detect_dns_exfil(dns_rows, self.thresholds))

        # statistical baseline, evaluated per minute
        findings.extend(self._run_baseline(flow_rows))

        # score, suppress, persist, feed threat board
        emitted = []
        for f in findings:
            score_finding(f)
            if not self.suppressor.should_emit(f["rule_name"], f["src_ip"]):
                continue
            repeats = self.suppressor.suppressed_repeats(f["rule_name"], f["src_ip"])
            q.insert_alert(self.conn, int(time.time()), f["rule_name"],
                           f["severity"], f["src_ip"], f.get("dst_ip"),
                           f["reason"], f.get("evidence", {}))
            self.threat.add_finding(f)
            emitted.append(f)

        return emitted

    def _run_baseline(self, flow_rows):
        """Accumulate per-minute host volume; check when the minute rolls over."""
        findings = []
        for f in flow_rows:
            minute = f["bucket_ts"] // 60
            if self._last_minute is None:
                self._last_minute = minute
            if minute > self._last_minute:
                for host, acc in self._minute_acc.items():
                    r = self.baseline.observe_and_check(host, acc["bytes"], acc["conns"])
                    if r:
                        findings.append(r)
                self._minute_acc.clear()
                self._last_minute = minute
            acc = self._minute_acc[f["src_ip"]]
            acc["bytes"] += f["byte_count"]
            acc["conns"] += f["packet_count"]
        return findings

    def threat_board(self):
        return self.threat.board()
