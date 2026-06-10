"""
backend/agent.py

Deterministic TAC-style reasoning engine for VoiceShield Agent.

Provides analyze_incident(raw_text: str) -> dict

Behavior and guarantees:
- Fully deterministic rule-based analysis using regex and conditional logic.
- No LLMs, no external services, no network calls.
- Produces a JSON-serializable dictionary with the exact schema required by the
  frontend dashboard and automated test harnesses.

Supported categories: SIP, RTP, DNS, TLS, NTP, UNKNOWN

Implements "#NTP FIRST" rule: if NTP/time-drift indicators exist together with SIP
authentication failures or TLS certificate validation failures, the module treats
NTP/time drift as the root cause and explains how clock skew breaks higher-layer
authentication and certificate validation.

Includes a __main__ test harness that prints JSON outputs for mandated test cases.
"""
from typing import List, Dict, Any
import re
import json


# ---------------------------
# Detection regex patterns
# ---------------------------
SIP_401_PATTERNS = [
    r"SIP\/2\.0\s*401\b",
    r"\b401 Unauthorized\b",
    r"WWW-Authenticate:\s*",
    r"\bAuthorization:\s*",
    r"\bnonce=\"",
    r"\bdigest\b",
]

RTP_PATTERNS = [
    r"\bone-?way\b",
    r"\bno incoming rtp\b",
    r"\bno rtp\b",
    r"\b0 packets\b",
    r"\bunidirectional\b",
    r"\breceived 0 packets\b",
    r"\brtp stream\b",
]

DNS_SRV_PATTERNS = [
    r"\bSRV\b",
    r"_sip\._tcp",
    r"_sip\._udp",
    r"\bSERVFAIL\b",
    r"\bNXDOMAIN\b",
    r"could not resolve",
    r"name or service not known",
    r"no such domain",
]

TLS_PATTERNS = [
    r"certificate has expired",
    r"certificate expired",
    r"certificate verify failed",
    r"ssl:.*verify failed",
    r"hostname .*doesn't match",
    r"subjectaltname",
    r"unable to get local issuer certificate",
    r"tls handshake failed",
    r"Verify return code: 10",
]

NTP_PATTERNS = [
    r"\bntp\b",
    r"chrony",
    r"ntpd",
    r"ntpdate",
    r"unsynchronized",
    r"stratum 16",
    r"clock skew",
    r"time drift",
    r"system clock unsynchronized",
]


# ---------------------------
# Helpers
# ---------------------------

def _extract_evidence(raw: str, patterns: List[str]) -> List[str]:
    """Return unique lines from raw that match any of the supplied regex patterns."""
    if not raw:
        return []

    lines = raw.splitlines()
    matched: List[str] = []
    for i, line in enumerate(lines):
        for pat in patterns:
            if re.search(pat, line, flags=re.IGNORECASE):
                snippet = line.strip()
                if snippet and snippet not in matched:
                    matched.append(snippet)
                break
    return matched


def _count_occurrences(raw: str, pattern: str) -> int:
    return len(re.findall(pattern, raw, flags=re.IGNORECASE))


def _clamp_score(value: int) -> int:
    if value < 0:
        return 0
    if value > 100:
        return 100
    return int(value)


def _base_unknown() -> Dict[str, Any]:
    return {
        "category": "UNKNOWN",
        "root_cause": "insufficient data to determine root cause",
        "evidence": [],
        "reasoning_steps": [
            "No deterministic signatures found in provided logs.",
            "Collect SIP traces, RTP captures, DNS dig outputs, TLS diagnostics, and NTP/chrony status.",
        ],
        "fix_recommendations": [
            "Collect targeted logs: SIP INVITE/REGISTER exchanges, RTP packet captures from both endpoints, `dig` for SRV, `openssl s_client` outputs, and `ntpq -pn` or `chronyc sources`.",
        ],
        "cli_commands": [
            "tcpdump -nni any -w capture.pcap 'port 5060 or udp portrange 10000-20000 or port 5061 or port 123 or port 53'",
        ],
        "confidence_score": 10,
    }


# ---------------------------
# Core analyzer
# ---------------------------
def analyze_incident(raw_text: str) -> Dict[str, Any]:
    """Deterministic rule-based analysis of raw incident text.

    Returns a dictionary exactly matching the required schema.
    """
    raw = raw_text or ""
    lower = raw.lower()

    # Collect evidence from all pattern sets (deduplicated preserving order)
    evidence: List[str] = []
    for extractor in (SIP_401_PATTERNS, RTP_PATTERNS, DNS_SRV_PATTERNS, TLS_PATTERNS, NTP_PATTERNS):
        for line in _extract_evidence(raw, extractor):
            if line not in evidence:
                evidence.append(line)

    # Flags and counts
    sip401_count = _count_occurrences(raw, r"SIP\/2\.0\s*401\b") + _count_occurrences(raw, r"\b401 Unauthorized\b")
    has_sip_auth_headers = bool(re.search(r"WWW-Authenticate:|Authorization:", raw, flags=re.IGNORECASE))
    has_rtp = len(_extract_evidence(raw, RTP_PATTERNS)) > 0
    has_dns_srv = len(_extract_evidence(raw, DNS_SRV_PATTERNS)) > 0
    has_tls = len(_extract_evidence(raw, TLS_PATTERNS)) > 0
    has_ntp = len(_extract_evidence(raw, NTP_PATTERNS)) > 0

    # Prepare common CLI commands required across reports
    common_cli = [
        "tcpdump -nni any -w capture.pcap 'port 5060 or port 5061 or udp portrange 10000-20000 or port 53 or port 123'",
        "tshark -r capture.pcap",
        "openssl s_client -connect <host>:<port> -showcerts",
        "dig _sip._tcp.example.com SRV +short",
        "nslookup -type=SRV _sip._tcp.example.com",
        "ntpq -pn",
        "chronyc sources",
    ]

    # #NTP FIRST rule
    if has_ntp and (has_tls or sip401_count > 0 or has_sip_auth_headers):
        category = "NTP"
        root_cause = "NTP/time drift causing higher-layer authentication and TLS validation failures"
        reasoning_steps: List[str] = []
        reasoning_steps.append("Detected NTP/time synchronization indicators in logs.")
        if has_tls:
            reasoning_steps.append(
                "TLS validation errors present; system clock skew can make valid certificates appear expired or not yet valid, failing TLS handshakes."
            )
        if sip401_count > 0 or has_sip_auth_headers:
            reasoning_steps.append(
                "SIP authentication failures (401) or WWW-Authenticate/Authorization exchanges present; clock skew can invalidate digest nonces or produce timestamp-related rejections."
            )
        reasoning_steps.append("Per '#NTP FIRST' rule, correct system time before higher-layer remediation to avoid wasted effort.")

        fix_recommendations = [
            "Verify and restore NTP synchronization on affected hosts (ntpq -pn or chronyc sources).",
            "If unsynchronized, perform a controlled time correction: use 'chronyc makestep' or 'sudo ntpdate -u pool.ntp.org' where appropriate.",
            "Restart affected services (SIP stack, TLS-terminating services) after time correction and retest registrations and calls.",
        ]

        cli_commands = [
            "ntpq -pn",
            "chronyc sources",
            "sudo systemctl status ntpd || sudo systemctl status chronyd",
            "sudo ntpdate -u pool.ntp.org  # one-time sync (use carefully in production)",
            "date -u  # verify system clock",
        ] + common_cli

        # Confidence strongly elevated when both NTP and higher-layer errors present
        confidence = 85
        if sip401_count > 0:
            confidence += 5
        if has_tls:
            confidence += 5
        confidence = _clamp_score(confidence)

        return {
            "category": category,
            "root_cause": root_cause,
            "evidence": evidence,
            "reasoning_steps": reasoning_steps,
            "fix_recommendations": fix_recommendations,
            "cli_commands": cli_commands,
            "confidence_score": confidence,
        }

    # TLS-specific detection (after NTP-first)
    if has_tls:
        category = "TLS"
        tls_lines = _extract_evidence(raw, TLS_PATTERNS)
        for ln in tls_lines:
            if ln not in evidence:
                evidence.append(ln)

        reasoning_steps = []
        fix_recommendations = []
        cli_commands = []

        # Expired certificate
        if re.search(r"certificate has expired|certificate expired|Verify return code: 10", raw, flags=re.IGNORECASE):
            root_cause = "TLS certificate expired"
            reasoning_steps.append("Logs explicitly indicate certificate expiration or an OpenSSL verify return code for expiry.")
            fix_recommendations.extend([
                "Renew or replace the expired certificate on the affected service.",
                "Install full certificate chain (intermediate CA) if missing using appropriate server configuration.",
                "Validate system clocks on clients and servers before re-installing certificates.",
            ])
            confidence = 90
        # Hostname mismatch
        elif re.search(r"hostname .*doesn\'t match|subjectaltname|SAN mismatch", raw, flags=re.IGNORECASE):
            root_cause = "TLS certificate hostname/SAN mismatch"
            reasoning_steps.append("Certificate validation errors point to hostname or SAN mismatch between served certificate and requested host.")
            fix_recommendations.extend([
                "Replace certificate to include correct CN and SAN entries for the service hostnames.",
                "Ensure clients use the expected TLS SNI/hostname when initiating the handshake.",
            ])
            confidence = 85
        else:
            root_cause = "TLS certificate validation failure (expired, hostname mismatch, or CA chain issue)"
            reasoning_steps.append(
                "TLS/SSL verification failures observed; could be caused by expiry, hostname mismatch, missing intermediates, or trust chain problems."
            )
            fix_recommendations.extend([
                "Run 'openssl s_client -connect <host>:<port> -showcerts' to inspect certificate chain and validity.",
                "Install any missing intermediate CA certificates, and confirm trust anchors on clients.",
            ])
            confidence = 75

        cli_commands.extend([
            "openssl s_client -connect <host>:<port> -showcerts",
            "openssl x509 -in cert.pem -noout -text | grep -E 'Not After|Subject|Issuer'",
            "tcpdump -nni any port 5061 and host <peer> -w tls_sip_capture.pcap",
            "tshark -r tls_sip_capture.pcap -Y 'ssl || tls' -V",
        ])

        return {
            "category": category,
            "root_cause": root_cause,
            "evidence": evidence,
            "reasoning_steps": reasoning_steps,
            "fix_recommendations": fix_recommendations,
            "cli_commands": cli_commands + common_cli,
            "confidence_score": _clamp_score(confidence),
        }

    # SIP 401 authentication loop detection
    if sip401_count >= 1:
        category = "SIP"
        sip_lines = _extract_evidence(raw, SIP_401_PATTERNS)
        for ln in sip_lines:
            if ln not in evidence:
                evidence.append(ln)

        reasoning_steps = []
        fix_recommendations = []
        cli_commands = []

        reasoning_steps.append(f"Detected SIP 401 Unauthorized responses (count={sip401_count}).")

        # Specific hints
        if re.search(r"stale", raw, flags=re.IGNORECASE):
            root_cause = "Digest authentication stale/nonce lifecycle issues (possible clock/nonce mismatch)"
            reasoning_steps.append("Logs indicate 'stale' nonces; clients may be reusing expired nonces or server expects refreshed nonces.")
            confidence = 80
        elif re.search(r"invalid password|wrong password|403 Forbidden", raw, flags=re.IGNORECASE):
            root_cause = "Invalid credentials or account lockout on authentication server"
            reasoning_steps.append("Evidence suggests credentials are rejected by the authentication backend or account is locked/disabled.")
            confidence = 85
        else:
            root_cause = "SIP digest authentication failure (credentials, realm, nonce, or server policy mismatch)"
            reasoning_steps.append("401 responses point to authentication failures; inspect WWW-Authenticate and Authorization header exchanges for realm/nonce mismatches.")
            confidence = 70

        fix_recommendations.extend([
            "Capture SIP REGISTER/INVITE exchanges and inspect WWW-Authenticate and Authorization headers for realm, nonce, and algorithm mismatches.",
            "Verify username/password and authentication realm configured on endpoints and authentication servers.",
            "Check server-side auth logs for lockouts, rate limiting, or unusual rejections.",
            "Ensure system clocks are synchronized (see NTP checks) if digest nonces are time-limited.",
        ])

        cli_commands.extend([
            "tcpdump -nni any -w sip_capture.pcap 'port 5060'",
            "ngrep -d any -W byline 'REGISTER|INVITE|401|WWW-Authenticate|Authorization' port 5060",
            "tshark -r sip_capture.pcap -Y 'sip' -V",
        ])

        return {
            "category": category,
            "root_cause": root_cause,
            "evidence": evidence,
            "reasoning_steps": reasoning_steps,
            "fix_recommendations": fix_recommendations,
            "cli_commands": cli_commands + common_cli,
            "confidence_score": _clamp_score(confidence),
        }

    # One-way RTP detection
    if has_rtp:
        category = "RTP"
        rtp_lines = _extract_evidence(raw, RTP_PATTERNS)
        for ln in rtp_lines:
            if ln not in evidence:
                evidence.append(ln)

        reasoning_steps = []
        fix_recommendations = []
        cli_commands = []

        reasoning_steps.append("Detected indicators of RTP asymmetry or missing RTP in one direction.")

        if re.search(r"no incoming rtp|received 0 packets|0 packets", raw, flags=re.IGNORECASE):
            root_cause = "No incoming RTP on one direction (likely NAT traversal, firewall or port blocking)"
            reasoning_steps.append("Zero or no incoming RTP packets for an endpoint suggests NAT/firewall blocking, missing port forwarding, or asymmetric routing.")
            fix_recommendations.extend([
                "Check NAT and firewall rules; ensure RTP port ranges are allowed and pinholed for the call duration.",
                "Verify SDP offers/answers contain correct RTP ports and matched codecs.",
                "Collect packet captures on both endpoint networks to compare flow directions.",
            ])
            confidence = 80
        else:
            root_cause = "RTP flow asymmetry or media negotiation problem (codec mismatch, firewall/NAT, or endpoint bug)"
            reasoning_steps.append("RTP asymmetry may be caused by codec negotiation issues, firewall/NAT behavior, or an endpoint implementation bug.")
            fix_recommendations.extend([
                "Validate codec lists and SDP negotiation between endpoints.",
                "Check RTP/RTCP ports and firewall rules.",
                "Gather RTP and SIP traces from both ends for correlation.",
            ])
            confidence = 65

        cli_commands.extend([
            "tcpdump -nni any udp and portrange 10000-20000 -w rtp_capture.pcap",
            "tshark -r rtp_capture.pcap -Y 'rtp' -T fields -e ip.src -e ip.dst -e udp.srcport -e udp.dstport -e rtp.seq",
            "rtpbreak -r rtp_capture.pcap  # analyze RTP streams",
        ])

        return {
            "category": category,
            "root_cause": root_cause,
            "evidence": evidence,
            "reasoning_steps": reasoning_steps,
            "fix_recommendations": fix_recommendations,
            "cli_commands": cli_commands + common_cli,
            "confidence_score": _clamp_score(confidence),
        }

    # DNS SRV lookup failure
    if has_dns_srv:
        category = "DNS"
        dns_lines = _extract_evidence(raw, DNS_SRV_PATTERNS)
        for ln in dns_lines:
            if ln not in evidence:
                evidence.append(ln)

        reasoning_steps = []
        fix_recommendations = []
        cli_commands = []

        reasoning_steps.append("Detected DNS SRV/A/resolve failures impacting SIP service discovery.")

        if re.search(r"servfail|server failed", raw, flags=re.IGNORECASE):
            root_cause = "DNS server failure or misconfiguration (SERVFAIL)"
            reasoning_steps.append("SERVFAIL responses indicate authoritative DNS server problems, zone misconfiguration, or DNSSEC validation failures.")
            confidence = 85
        elif re.search(r"nxdomain|no such domain|could not resolve", raw, flags=re.IGNORECASE):
            root_cause = "Missing or misconfigured SRV records (NXDOMAIN or unresolved)"
            reasoning_steps.append("NXDOMAIN or resolution failure indicates SRV records are missing, misnamed, or not propagated to authoritative servers.")
            confidence = 80
        else:
            root_cause = "SRV/DNS resolution problems affecting SIP routing"
            reasoning_steps.append("SRV/DNS lookup failures will prevent clients from finding SIP servers (e.g., CUCM).")
            confidence = 75

        fix_recommendations.extend([
            "Verify SRV records for SIP using 'dig _sip._tcp.example.com SRV +short' and check authoritative servers.",
            "Confirm DNS zone configuration, delegation, and propagation across authoritative name servers.",
            "Ensure clients are using correct resolvers and have no local overrides (hosts file).",
        ])

        cli_commands.extend([
            "dig _sip._tcp.example.com SRV +short",
            "nslookup -type=SRV _sip._tcp.example.com",
            "tcpdump -nni any port 53 -w dns_capture.pcap",
        ])

        return {
            "category": category,
            "root_cause": root_cause,
            "evidence": evidence,
            "reasoning_steps": reasoning_steps,
            "fix_recommendations": fix_recommendations,
            "cli_commands": cli_commands + common_cli,
            "confidence_score": _clamp_score(confidence),
        }

    # Default unknown
    return _base_unknown()


# ---------------------------
# Test samples when executed directly
# ---------------------------
if __name__ == "__main__":
    samples = {
        "sip_401_loop": """
        Apr 10 12:00:01 pbx1 sip: Received: SIP/2.0 401 Unauthorized
        Apr 10 12:00:01 pbx1 sip: WWW-Authenticate: Digest realm=\"sip.example.com\", nonce=\"abc123\"
        Apr 10 12:00:02 pbx1 sip: Sending REGISTER
        Apr 10 12:00:02 pbx1 sip: Received: SIP/2.0 401 Unauthorized
        Apr 10 12:00:03 pbx1 sip: Sending REGISTER
        Apr 10 12:00:03 pbx1 sip: Received: SIP/2.0 401 Unauthorized
        """,

        "one_way_rtp": """
        2026-06-01 09:15:21 Router RTP: callid=abc123 - no incoming RTP from 10.1.2.3:16384
        2026-06-01 09:15:21 Router RTP: outgoing packets to 10.4.5.6:16386 350 packets
        2026-06-01 09:15:22 Endpoint debug: received 0 packets on RTP stream ssrc=23456
        """,

        "dns_srv_failure": """
        SIP client error: SRV lookup failed for _sip._tcp.example.com: SERVFAIL
        system resolver: could not resolve _sip._tcp.example.com SRV record - name or service not known
        """,

        "tls_expired": """
        TLS alert: certificate has expired
        ssl error: certificate verify failed (certificate has expired)
        openssl s_client reports: Verify return code: 10 (certificate has expired)
        """,

        "ntp_drift_causing_auth": """
        chronyd[1234]: System clock unsynchronized, stratum 16
        ntpdate[2345]: adjust time server unreachable
        SIP/2.0 401 Unauthorized
        ssl: certificate verify failed
        """,
    }

    for name, text in samples.items():
        result = analyze_incident(text)
        print(json.dumps({"sample": name, "analysis": result}, indent=2))
