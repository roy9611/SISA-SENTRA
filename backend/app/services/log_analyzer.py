"""
Log Analyzer — deep log analysis with brute-force detection,
suspicious IP tracking, error leak detection, and cross-line correlation.
"""

import re
from collections import Counter, defaultdict

from app.core.config import settings
from app.core.logging_config import logger
from app.models.schemas import Finding
from app.utils.patterns import (
    DEVICE_TYPE_VECTORS,
    ERROR_LEAK_PATTERN,
    FAILED_LOGIN_PATTERN,
    IP_ADDRESS_PATTERN,
    LOG_TYPE_VECTORS,
    PORT_PATTERN,
    RISK_MAP,
    SUSPICIOUS_IP_INDICATORS,
    TIMESTAMP_PATTERN,
    URI_PATTERN,
)


class LogAnalyzer:
    """
    Advanced log analysis engine with key-value aware extraction.
    """

    BRUTE_FORCE_THRESHOLD = 5  # N failed logins = brute force

    def analyze(self, content: str) -> dict:
        """
        Perform deep log analysis.
        Returns dict with findings, stats, and summary.
        """
        logger.info("Starting log analysis")
        lines = content.split("\n")
        total_lines = len(lines)

        # Chunk large logs
        chunk_size = settings.LOG_CHUNK_SIZE
        all_findings: list[Finding] = []
        failed_login_lines: list[int] = []
        ip_counter: Counter = Counter()
        ip_lines: dict[str, list[int]] = defaultdict(list)
        error_count = 0
        suspicious_lines: list[int] = []

        for chunk_start in range(0, total_lines, chunk_size):
            chunk_end = min(chunk_start + chunk_size, total_lines)
            chunk = lines[chunk_start:chunk_end]

            for offset, line in enumerate(chunk):
                line_num = chunk_start + offset + 1  # 1-indexed
                if not line.strip():
                    continue

                # Failed login detection
                if FAILED_LOGIN_PATTERN.search(line):
                    failed_login_lines.append(line_num)
                    finding = Finding(
                        type="failed_login",
                        risk=RISK_MAP.get("failed_login", "medium"),
                        line=line_num,
                    )
                    all_findings.append(finding)

                # IP address tracking
                ips = IP_ADDRESS_PATTERN.findall(line)
                for ip in ips:
                    if ip not in ("127.0.0.1", "0.0.0.0"):
                        ip_counter[ip] += 1
                        ip_lines[ip].append(line_num)

                # Suspicious IP indicators
                if SUSPICIOUS_IP_INDICATORS.search(line):
                    suspicious_lines.append(line_num)
                    finding = Finding(
                        type="suspicious_ip",
                        risk=RISK_MAP.get("suspicious_ip", "high"),
                        line=line_num,
                    )
                    all_findings.append(finding)

                # Error leak detection
                if ERROR_LEAK_PATTERN.search(line):
                    error_count += 1
                    finding = Finding(
                        type="error_leak",
                        risk=RISK_MAP.get("error_leak", "medium"),
                        line=line_num,
                    )
                    all_findings.append(finding)

        # ── Post-processing ───────────────────────────────────────────────────
        stats = {
            "total_lines": total_lines,
            "unique_ips": len(ip_counter),
            "failed_logins": len(failed_login_lines),
            "errors_detected": error_count,
            "suspicious_indicators": len(suspicious_lines),
        }

        # Brute force detection
        for ip, count in ip_counter.items():
            if count >= self.BRUTE_FORCE_THRESHOLD:
                # Check if this IP is associated with failed logins
                common_lines = set(ip_lines[ip]) & set(failed_login_lines)
                if len(common_lines) >= self.BRUTE_FORCE_THRESHOLD:
                    finding = Finding(
                        type="brute_force",
                        risk=RISK_MAP.get("brute_force", "critical"),
                        line=min(common_lines) if common_lines else 1,
                    )
                    all_findings.append(finding)

        # ── Entity Extraction ─────────────────────────────────────────────────
        extracted = {}
        unique_ips_list = list(ip_counter.keys())

        # 1. Forensic Summary (Timestamp, Log Type, Device)
        for line in lines:
            if not extracted.get("timestamp"):
                if tm := TIMESTAMP_PATTERN.search(line):
                    extracted["timestamp"] = tm.group(1)
            
            if not extracted.get("log_type"):
                for vector in LOG_TYPE_VECTORS:
                    if vector in line.lower():
                        extracted["log_type"] = vector.capitalize()
                        break
            
            if not extracted.get("device_type"):
                for vector in DEVICE_TYPE_VECTORS:
                    if vector in line.lower():
                        extracted["device_type"] = vector.title()
                        break

        # 2. Network Vector (IPs & Ports) - Optimized for Key-Value Logs (F5, etc)
        # Source/Client IP
        # Priority 1: Specific F5/ASM keys
        f5_src = re.search(r'ip_client\s*[:=]\s*["\']?([\d\.]+)["\']?', content, re.I)
        f5_dst = re.search(r'dest_ip\s*[:=]\s*["\']?([\d\.]+)["\']?', content, re.I)
        f5_uri = re.search(r'uri\s*[:=]\s*["\']?(/[^"\']+)["\']?', content, re.I)
        
        extracted_src = f5_src.group(1) if f5_src else None
        extracted_dst = f5_dst.group(1) if f5_dst else None
        if f5_uri: extracted["uri_target"] = f5_uri.group(1)
        
        # Priority 2: Standard keys
        if not extracted_src:
            src_match = re.search(r'(?:\b(?:from|src|source|client_ip)\s*[:=]\s*["\']?|\bsrc\s+)(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', content, re.IGNORECASE)
            extracted_src = src_match.group("ip") if src_match else None
            
        if not extracted_dst:
            dst_match = re.search(r'(?:\b(?:to|dst|dest|target_ip)\s*[:=]\s*["\']?|\bdst\s+)(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', content, re.IGNORECASE)
            extracted_dst = dst_match.group("ip") if dst_match else None
        
        if not extracted_src and unique_ips_list:
            extracted_src = unique_ips_list[0]
        if not extracted_dst and len(unique_ips_list) > 1:
            extracted_dst = unique_ips_list[1]
            
        if extracted_src:
            extracted["source_ip"] = extracted_src
        if extracted_dst:
            extracted["dest_ip"] = extracted_dst

        # 3. Ports & URI
        src_port_match = re.search(r'\b(?:src_port|sport|spt|spt|s_port)\s*[:=]\s*["\']?(\d+)', content, re.IGNORECASE)
        dst_port_match = re.search(r'\b(?:dest_port|dport|dpt|dpt|d_port|dest_port)\s*[:=]\s*["\']?(\d+)', content, re.IGNORECASE)
        
        if src_port_match:
            extracted["src_port"] = src_port_match.group(1)
        if dst_port_match:
            extracted["dst_port"] = dst_port_match.group(1)
            
        uri_match = re.search(r'\b(?:uri|request_uri|url|path)\s*[:=]\s*["\']?(/[^\s"\']*)', content, re.IGNORECASE)
        if uri_match:
            extracted["uri_target"] = uri_match.group(1)
        else:
            for line in lines:
                if um := URI_PATTERN.search(line):
                    extracted["uri_target"] = um.group(1)
                    break

        # Defaults
        extracted.setdefault("timestamp", "N/A")
        extracted.setdefault("log_type", "General")
        extracted.setdefault("device_type", "Workstation")
        extracted.setdefault("source_ip", "---")
        extracted.setdefault("dest_ip", "---")
        extracted.setdefault("src_port", "---")
        extracted.setdefault("dst_port", "---")
        extracted.setdefault("uri_target", "---")

        logger.info(f"Log analysis complete: {len(all_findings)} findings, stats={stats}")

        return {
            "findings": all_findings,
            "stats": stats,
            "extracted_entities": extracted,
        }
