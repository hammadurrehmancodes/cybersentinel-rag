"""
CyberSentinel - Log Analyzer
==============================
Parses raw firewall and system logs into structured security events.
Supports: Windows Firewall, Linux UFW, IPTables, SSH auth logs

This feeds directly into the RAG pipeline as structured context.
"""

import re
from datetime import datetime
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional


# ─────────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────────

@dataclass
class SecurityEvent:
    event_type: str          # brute_force, port_scan, suspicious_connection, etc.
    severity: str            # low, medium, high, critical
    source_ip: str
    destination_port: Optional[int]
    protocol: Optional[str]
    timestamp: Optional[str]
    count: int               # how many times this pattern appeared
    details: str             # human-readable description
    raw_lines: list = field(default_factory=list)


@dataclass
class LogAnalysisResult:
    events: list[SecurityEvent]
    summary: str
    total_lines: int
    suspicious_ips: list[str]
    top_attacked_ports: list[dict]
    time_range: dict
    log_type: str


# ─────────────────────────────────────────────
# Log Parsers
# ─────────────────────────────────────────────

class LogParser:
    """Detects log type and parses into structured events."""

    # Regex patterns for different log formats
    PATTERNS = {
        # Windows Firewall: "2024-01-15 03:22:11 DROP TCP 192.168.1.1 10.0.0.1 54231 22"
        "windows_firewall": re.compile(
            r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+"
            r"(ALLOW|DROP|DENY)\s+"
            r"(\w+)\s+"
            r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+"
            r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+"
            r"(\d+)\s+(\d+)"
        ),
        
        # UFW: "Jan 15 03:22:11 hostname kernel: [UFW BLOCK] ... SRC=192.168.1.1 DST=10.0.0.1 ... DPT=22"
        "ufw": re.compile(
            r"(\w+\s+\d+\s+\d{2}:\d{2}:\d{2}).*"
            r"\[UFW\s+(BLOCK|ALLOW)\].*"
            r"SRC=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*"
            r"DST=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*"
            r"DPT=(\d+)"
        ),
        
        # IPTables: "Jan 15 03:22:11 hostname kernel: IN=eth0 ... SRC=192.168.1.1 DST=10.0.0.1 ... DPT=22"
        "iptables": re.compile(
            r"(\w+\s+\d+\s+\d{2}:\d{2}:\d{2}).*"
            r"SRC=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+"
            r"DST=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*"
            r"DPT=(\d+)"
        ),
        
        # SSH Auth: "Jan 15 03:22:11 hostname sshd[1234]: Failed password for root from 192.168.1.1 port 54231 ssh2"
        "ssh_auth": re.compile(
            r"(\w+\s+\d+\s+\d{2}:\d{2}:\d{2}).*"
            r"(Failed password|Invalid user|Accepted password|error: maximum authentication).*?"
            r"(?:for\s+(\w+)\s+)?from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
        ),
        
        # Generic IP extractor (fallback)
        "generic_ip": re.compile(
            r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
        )
    }

    # Sensitive ports worth flagging
    SENSITIVE_PORTS = {
        22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 443: "HTTPS", 445: "SMB", 1433: "MSSQL",
        1521: "Oracle", 3306: "MySQL", 3389: "RDP",
        5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
        27017: "MongoDB", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
    }

    def detect_log_type(self, log_text: str) -> str:
        """Auto-detect the log format."""
        if "[UFW" in log_text:
            return "ufw"
        elif "DROP TCP" in log_text or "ALLOW TCP" in log_text:
            return "windows_firewall"
        elif "Failed password" in log_text or "Invalid user" in log_text:
            return "ssh_auth"
        elif "DPT=" in log_text and "SRC=" in log_text:
            return "iptables"
        else:
            return "generic"

    def parse(self, log_text: str) -> LogAnalysisResult:
        """Main parse method - auto-detects format and extracts events."""
        
        lines = [l.strip() for l in log_text.strip().split('\n') if l.strip()]
        log_type = self.detect_log_type(log_text)
        
        # Extract raw records
        records = self._extract_records(lines, log_type)
        
        # Analyze patterns
        events = self._detect_attack_patterns(records, log_type)
        
        # Build summary stats
        all_ips = [r.get("src_ip") for r in records if r.get("src_ip")]
        all_ports = [r.get("dst_port") for r in records if r.get("dst_port")]
        
        ip_counts = defaultdict(int)
        port_counts = defaultdict(int)
        for ip in all_ips:
            ip_counts[ip] += 1
        for port in all_ports:
            if port:
                port_counts[port] += 1
        
        suspicious_ips = [
            ip for ip, count in ip_counts.items()
            if count > 5  # threshold
        ]
        
        top_ports = sorted(
            [{"port": p, "service": self.SENSITIVE_PORTS.get(p, "Unknown"), "count": c}
             for p, c in port_counts.items()],
            key=lambda x: x["count"], reverse=True
        )[:10]
        
        summary = self._generate_raw_summary(events, records, log_type)
        
        return LogAnalysisResult(
            events=events,
            summary=summary,
            total_lines=len(lines),
            suspicious_ips=suspicious_ips,
            top_attacked_ports=top_ports,
            time_range=self._extract_time_range(records),
            log_type=log_type
        )

    def _extract_records(self, lines: list, log_type: str) -> list:
        """Extract structured records from raw log lines."""
        records = []
        
        for line in lines:
            record = {"raw": line, "src_ip": None, "dst_port": None,
                     "action": None, "timestamp": None, "protocol": None}
            
            if log_type == "windows_firewall":
                m = self.PATTERNS["windows_firewall"].search(line)
                if m:
                    record.update({
                        "timestamp": m.group(1),
                        "action": m.group(2),
                        "protocol": m.group(3),
                        "src_ip": m.group(4),
                        "dst_port": int(m.group(7))
                    })
            
            elif log_type == "ufw":
                m = self.PATTERNS["ufw"].search(line)
                if m:
                    record.update({
                        "timestamp": m.group(1),
                        "action": m.group(2),
                        "src_ip": m.group(3),
                        "dst_port": int(m.group(5))
                    })
            
            elif log_type == "iptables":
                m = self.PATTERNS["iptables"].search(line)
                if m:
                    record.update({
                        "timestamp": m.group(1),
                        "src_ip": m.group(2),
                        "dst_port": int(m.group(4))
                    })
            
            elif log_type == "ssh_auth":
                m = self.PATTERNS["ssh_auth"].search(line)
                if m:
                    record.update({
                        "timestamp": m.group(1),
                        "action": "FAIL" if "Failed" in m.group(2) or "Invalid" in m.group(2) else "SUCCESS",
                        "src_ip": m.group(4)
                    })
            
            else:
                # Generic: just extract IPs
                ips = self.PATTERNS["generic_ip"].findall(line)
                if ips:
                    record["src_ip"] = ips[0]
            
            if record["src_ip"]:
                records.append(record)
        
        return records

    def _detect_attack_patterns(self, records: list, log_type: str) -> list[SecurityEvent]:
        """Detect attack patterns from structured records."""
        events = []
        
        # Group by source IP
        ip_records = defaultdict(list)
        for r in records:
            if r["src_ip"]:
                ip_records[r["src_ip"]].append(r)
        
        for ip, ip_recs in ip_records.items():
            ports_targeted = list(set(r["dst_port"] for r in ip_recs if r["dst_port"]))
            failed_count = sum(1 for r in ip_recs if r.get("action") in ["DROP", "DENY", "BLOCK", "FAIL"])
            
            # ── Brute Force Detection ──
            if log_type == "ssh_auth":
                fail_count = sum(1 for r in ip_recs if r.get("action") == "FAIL")
                if fail_count >= 5:
                    severity = "critical" if fail_count > 50 else "high" if fail_count > 20 else "medium"
                    events.append(SecurityEvent(
                        event_type="brute_force",
                        severity=severity,
                        source_ip=ip,
                        destination_port=22,
                        protocol="SSH",
                        timestamp=ip_recs[0].get("timestamp"),
                        count=fail_count,
                        details=f"SSH brute force: {fail_count} failed login attempts from {ip}",
                        raw_lines=[r["raw"] for r in ip_recs[:3]]
                    ))
            
            # ── Port Scan Detection ──
            elif len(ports_targeted) > 10:
                severity = "high" if len(ports_targeted) > 50 else "medium"
                sensitive_found = [p for p in ports_targeted if p in self.SENSITIVE_PORTS]
                events.append(SecurityEvent(
                    event_type="port_scan",
                    severity=severity,
                    source_ip=ip,
                    destination_port=None,
                    protocol="TCP/UDP",
                    timestamp=ip_recs[0].get("timestamp"),
                    count=len(ports_targeted),
                    details=(
                        f"Port scan detected: {ip} probed {len(ports_targeted)} ports. "
                        f"Sensitive ports found: {[self.SENSITIVE_PORTS[p] + '(' + str(p) + ')' for p in sensitive_found]}"
                        if sensitive_found else
                        f"Port scan detected: {ip} probed {len(ports_targeted)} ports."
                    ),
                    raw_lines=[r["raw"] for r in ip_recs[:3]]
                ))
            
            # ── Repeated Blocked Connections ──
            elif failed_count >= 20:
                severity = "high" if failed_count > 100 else "medium"
                top_port = max(set(r["dst_port"] for r in ip_recs if r["dst_port"]),
                              key=lambda p: sum(1 for r in ip_recs if r["dst_port"] == p),
                              default=None)
                service = self.SENSITIVE_PORTS.get(top_port, "Unknown") if top_port else "Unknown"
                events.append(SecurityEvent(
                    event_type="repeated_blocked",
                    severity=severity,
                    source_ip=ip,
                    destination_port=top_port,
                    protocol="TCP",
                    timestamp=ip_recs[0].get("timestamp"),
                    count=failed_count,
                    details=f"Suspicious activity: {failed_count} blocked connections from {ip}, mainly targeting {service} port {top_port}",
                    raw_lines=[r["raw"] for r in ip_recs[:3]]
                ))
            
            # ── Sensitive Port Access ──
            sensitive_targeted = [p for p in ports_targeted if p in self.SENSITIVE_PORTS]
            if sensitive_targeted and failed_count < 20:
                for port in sensitive_targeted:
                    events.append(SecurityEvent(
                        event_type="sensitive_port_access",
                        severity="medium",
                        source_ip=ip,
                        destination_port=port,
                        protocol="TCP",
                        timestamp=ip_recs[0].get("timestamp"),
                        count=sum(1 for r in ip_recs if r["dst_port"] == port),
                        details=f"Connection attempts to sensitive port {self.SENSITIVE_PORTS[port]} ({port}) from {ip}",
                        raw_lines=[r["raw"] for r in ip_recs[:2]]
                    ))
        
        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        events.sort(key=lambda e: severity_order.get(e.severity, 4))
        
        return events

    def _generate_raw_summary(self, events: list, records: list, log_type: str) -> str:
        """Generate a structured summary string for the RAG pipeline."""
        critical = [e for e in events if e.severity == "critical"]
        high = [e for e in events if e.severity == "high"]
        medium = [e for e in events if e.severity == "medium"]
        
        lines = [
            f"LOG ANALYSIS SUMMARY",
            f"Log Type: {log_type.upper()}",
            f"Total Records Analyzed: {len(records)}",
            f"Total Events Detected: {len(events)}",
            f"Critical: {len(critical)}, High: {len(high)}, Medium: {len(medium)}",
            "",
            "DETECTED EVENTS:"
        ]
        
        for event in events:
            lines.append(
                f"[{event.severity.upper()}] {event.event_type} | "
                f"IP: {event.source_ip} | "
                f"Port: {event.destination_port or 'Multiple'} | "
                f"Count: {event.count} | "
                f"{event.details}"
            )
        
        return "\n".join(lines)

    def _extract_time_range(self, records: list) -> dict:
        """Extract the time range covered by the logs."""
        timestamps = [r["timestamp"] for r in records if r.get("timestamp")]
        if not timestamps:
            return {"start": "Unknown", "end": "Unknown"}
        return {
            "start": timestamps[0],
            "end": timestamps[-1],
            "duration": f"{len(timestamps)} log entries"
        }


# ─────────────────────────────────────────────
# Quick test
# ─────────────────────────────────────────────
if __name__ == "__main__":
    # Test with sample UFW log
    sample_log = """
Jan 15 03:22:11 server kernel: [UFW BLOCK] IN=eth0 SRC=185.220.101.45 DST=10.0.0.1 DPT=22
Jan 15 03:22:12 server kernel: [UFW BLOCK] IN=eth0 SRC=185.220.101.45 DST=10.0.0.1 DPT=22
Jan 15 03:22:13 server kernel: [UFW BLOCK] IN=eth0 SRC=185.220.101.45 DST=10.0.0.1 DPT=22
Jan 15 03:22:14 server kernel: [UFW BLOCK] IN=eth0 SRC=185.220.101.45 DST=10.0.0.1 DPT=22
Jan 15 03:22:15 server kernel: [UFW BLOCK] IN=eth0 SRC=185.220.101.45 DST=10.0.0.1 DPT=22
Jan 15 03:22:16 server kernel: [UFW BLOCK] IN=eth0 SRC=185.220.101.45 DST=10.0.0.1 DPT=22
Jan 15 03:22:17 server kernel: [UFW BLOCK] IN=eth0 SRC=185.220.101.45 DST=10.0.0.1 DPT=22
Jan 15 03:22:18 server kernel: [UFW BLOCK] IN=eth0 SRC=185.220.101.45 DST=10.0.0.1 DPT=22
Jan 15 03:22:19 server kernel: [UFW BLOCK] IN=eth0 SRC=185.220.101.45 DST=10.0.0.1 DPT=22
Jan 15 03:22:20 server kernel: [UFW BLOCK] IN=eth0 SRC=185.220.101.45 DST=10.0.0.1 DPT=22
Jan 15 03:22:21 server kernel: [UFW BLOCK] IN=eth0 SRC=45.33.32.156 DST=10.0.0.1 DPT=80
Jan 15 03:22:22 server kernel: [UFW BLOCK] IN=eth0 SRC=45.33.32.156 DST=10.0.0.1 DPT=443
Jan 15 03:22:23 server kernel: [UFW BLOCK] IN=eth0 SRC=45.33.32.156 DST=10.0.0.1 DPT=22
Jan 15 03:22:24 server kernel: [UFW BLOCK] IN=eth0 SRC=45.33.32.156 DST=10.0.0.1 DPT=3306
Jan 15 03:22:25 server kernel: [UFW BLOCK] IN=eth0 SRC=45.33.32.156 DST=10.0.0.1 DPT=3389
Jan 15 03:22:26 server kernel: [UFW BLOCK] IN=eth0 SRC=45.33.32.156 DST=10.0.0.1 DPT=21
Jan 15 03:22:27 server kernel: [UFW BLOCK] IN=eth0 SRC=45.33.32.156 DST=10.0.0.1 DPT=8080
Jan 15 03:22:28 server kernel: [UFW BLOCK] IN=eth0 SRC=45.33.32.156 DST=10.0.0.1 DPT=1433
Jan 15 03:22:29 server kernel: [UFW BLOCK] IN=eth0 SRC=45.33.32.156 DST=10.0.0.1 DPT=27017
Jan 15 03:22:30 server kernel: [UFW BLOCK] IN=eth0 SRC=45.33.32.156 DST=10.0.0.1 DPT=6379
Jan 15 03:22:31 server kernel: [UFW BLOCK] IN=eth0 SRC=45.33.32.156 DST=10.0.0.1 DPT=5432
Jan 15 03:22:32 server kernel: [UFW BLOCK] IN=eth0 SRC=45.33.32.156 DST=10.0.0.1 DPT=5900
    """
    
    parser = LogParser()
    result = parser.parse(sample_log)
    
    print("=" * 60)
    print(result.summary)
    print("\nSuspicious IPs:", result.suspicious_ips)
    print("Top Ports:", result.top_attacked_ports[:5])
