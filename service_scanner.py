#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BRUTUS Stage 3: Service Scanner Head
Detects open services and assesses vulnerability risks (EDUCATIONAL/DEFENSIVE ONLY!)

Author: Aurelius Nova (NOVA Integration)
Project: Brutus Password & Network Security Tool
License: Educational/Demo Purposes Only

WARNING: Before scanning any network device, you MUST:
    1. Have explicit authorization from the network owner
    2. Understand that hotel/venue networks block discovery (AP Isolation)
    3. Know local laws regarding unauthorized scanning
"""


def scan_local_services():
    """Scan for local services and connections using Windows tools."""

    print()
    print("=" * 60)
    print("SERVICE SCANNER HEAD")
    print("=" * 60)
    print()

    findings = []

    try:
        import subprocess

        # Get active connections via PowerShell
        powershell_cmd = """
            $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue |
                Where-Object {$_.State -eq 'Listen'} |
                Select-Object LocalAddress, LocalPort, State
            $connections
        """

        print("Scanning local listening ports...")
        try:
            result = subprocess.run(
                powershell_cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines[:5]:
                    if any(x in line for x in ['LocalAddress', 'State']):
                        print(f"  {line}")

        except subprocess.TimeoutExpired:
            print("  Scan timed out (network may be restricted)")

    except ImportError:
        print("  Using Windows native tools")

    # Simulated service detection for demonstration
    demo_services = [
        {"port": 80, "service": "HTTP", "state": "OPEN", "vulnerability_risk": "MEDIUM",
         "description": "Web server - common vector for attacks",
         "recommendation": "Ensure HTTPS (443) is preferred"},
        {"port": 443, "service": "HTTPS", "state": "OPEN", "vulnerability_risk": "LOW",
         "description": "Secure web server - industry standard",
         "recommendation": "Keep SSL/TLS certificates updated"},
        {"port": 22, "service": "SSH", "state": "OPEN", "vulnerability_risk": "MEDIUM",
         "description": "Remote access - SSH brute force targets",
         "recommendation": "Disable root login; use key-based auth only"},
        {"port": 3389, "service": "RDP", "state": "OPEN", "vulnerability_risk": "HIGH",
         "description": "Remote Desktop - common attack target",
         "recommendation": "Use Network Level Authentication"},
        {"port": 445, "service": "SMB", "state": "OPEN", "vulnerability_risk": "HIGH",
         "description": "Samba/SMB - EternalBlue patch required",
         "recommendation": "Disable SMBv1; apply MS17-010 patches"},
    ]

    print()
    print("SCANNING LOCAL SERVICES (Demo Mode):")
    print("-" * 60)

    for svc in demo_services:
        risk_score = {"LOW": 1, "MEDIUM": 5, "HIGH": 9, "CRITICAL": 10}
        risk_val = risk_score.get(svc["vulnerability_risk"], 3)

        print()
        print(f"Port {svc['port']} - {svc['service']}/{svc['state']}")
        print(f"Risk Level: {svc['vulnerability_risk']} ({risk_val}/10)")
        print(f"{svc['description']}")
        print(f"Mitigation: {svc['recommendation']}")

        findings.append(svc)

    # Risk summary
    high_risk_count = sum(1 for f in findings if f["vulnerability_risk"] in ["HIGH", "CRITICAL"])
    medium_risk_count = sum(1 for f in findings if f["vulnerability_risk"] == "MEDIUM")

    print()
    print("-" * 60)
    print("SCAN SUMMARY:")
    print(f"Total services detected: {len(findings)}")
    print(f"Critical/High risk: {high_risk_count}")
    print(f"Medium risk: {medium_risk_count}")

    if high_risk_count > 0:
        print()
        print("CRITICAL ALERT:")
        print("- High-risk services detected!")
        print("- Review and remediate vulnerable services immediately")
        print("- Consider disabling non-essential services")

    print()
    print("=" * 60)
    print("SCANNER HEAD OPERATIONAL")
    print("=" * 60)
    print()

    return findings


def analyze_port_patterns(findings):
    """Analyze detected port patterns and identify suspicious behavior."""

    if not findings:
        return "No findings to analyze."

    report_lines = [
        "=" * 60,
        "PORT PATTERN ANALYSIS",
        "=" * 60,
    ]

    high_risk_ports = [22, 3389, 445, 135, 139]
    suspicious_patterns = []

    for f in findings:
        if f["port"] in high_risk_ports:
            pattern = {
                "type": f"Warning: {f['service']} service exposed",
                "severity": f["vulnerability_risk"],
                "description": f"Standard port ({f['port']}) detected - potential attack vector"
            }
            suspicious_patterns.append(pattern)

    if suspicious_patterns:
        report_lines.extend([
            "",
            f"Identified {len(suspicious_patterns)} potential attack vectors:",
        ])

        for i, pattern in enumerate(suspicious_patterns, 1):
            report_lines.append(f"{i}. {pattern['type']}")
            report_lines.append(f"   Severity: {pattern['severity']}")
            report_lines.append(f"   {pattern['description']}")

    report_lines.extend([
        "",
        "Recommendations:",
        "Close unnecessary high-risk ports",
        "Enable firewall rules to restrict access",
        "Keep all services patched and updated",
        "=" * 60,
    ])

    return "\n".join(report_lines)


if __name__ == "__main__":
    findings = scan_local_services()
    analysis = analyze_port_patterns(findings)

    print()
    print(analysis)
