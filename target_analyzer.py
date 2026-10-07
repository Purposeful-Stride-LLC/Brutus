#!/usr/bin/env python3
"""
BRUTUS Target Analyzer Module
Scans authorized targets for open ports/services and matches against rainbow table.
Localhost + authorized IP scanning only (with human approval).
"""

import socket
import json
from datetime import datetime
from pathlib import Path


class TargetAnalyzer:
    """
    Analyzes network targets for open ports and services.
    Works on localhost or authorized remote IPs only.
    """

    DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900]
    PORT_SERVICES = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'SMB',
        993: 'IMAPS',
        995: 'POP3S',
        1433: 'MSSQL',
        1521: 'Oracle',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        5900: 'VNC'
    }

    def __init__(self, authorized_file=None):
        self.ports_to_scan = list(self.DEFAULT_PORTS)
        if authorized_file and Path(authorized_file).exists():
            with open(authorized_file, 'r') as f:
                self.authorized_targets = {line.strip().lower() for line in f if line.strip()}
        else:
            self.authorized_targets = {'localhost', '127.0.0.1'}

    def scan_target(self, target_ip='localhost'):
        """Scan a single target for open ports."""
        results = []

        # Normalize target to hostname or IP
        try:
            if target_ip not in ['localhost', '127.0.0.1']:
                addr_info = socket.getaddrinfo(target_ip, None)
                if not addr_info:
                    return {'error': f'Unknown target: {target_ip}'}
        except Exception as e:
            return {'error': str(e)}

        print(f"\n{'='*70}")
        print(f"TARGET ANALYZER: Scanning {target_ip}")
        print("="*70)

        for port in self.ports_to_scan:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)  # 1 second timeout per probe

                result = sock.connect_ex((target_ip, port))

                if result == 0:  # Port is open
                    service = self.PORT_SERVICES.get(port, 'Unknown')

                    results.append({
                        'port': port,
                        'service': service,
                        'state': 'OPEN',
                        'risk_level': self._assess_risk(service)
                    })

                    print(f"  [PORT {port:>3}] {service:<12} - OPEN")

                sock.close()

            except Exception as e:
                pass

        return results

    def _assess_risk(self, service):
        """Assess risk level based on service type."""
        if service in ['Telnet', 'FTP', 'SSH', 'SMB']:
            return 'HIGH'  # Unencrypted or weak auth services
        elif service in ['HTTP', 'SMTP', 'DNS', 'MySQL', 'PostgreSQL', 'Oracle', 'MSSQL']:
            return 'MEDIUM'  # Common services, may have vulnerabilities
        else:
            return 'LOW'

    def analyze_all_targets(self):
        """Analyze all authorized targets."""
        results = []

        for target in self.authorized_targets:
            if target in ['localhost', '127.0.0.1']:
                results.extend(self.scan_target(target))
            elif any(host in host or target.split('.')[-1] in host
                      for host in results):  # Skip unauthorized remote targets
                pass

        return results

    def generate_risk_report(self, port_results):
        """Generate summary risk report."""
        if not port_results:
            return "No open ports found."

        high_risk = [p for p in port_results if p['risk_level'] == 'HIGH']
        medium_risk = [p for p in port_results if p['risk_level'] == 'MEDIUM']

        summary = f"""
BRUTUS TARGET ANALYSIS REPORT
==============================
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Total ports scanned: {len(self.ports_to_scan)}
Open ports found: {len(port_results)}

HIGH RISK SERVICES ({len(high_risk)}):
"""

        for p in high_risk:
            summary += f"  - Port {p['port']}: {p['service']} (Risk Level: {p['risk_level']})\n"

        summary += """
MEDIUM RISK SERVICES ({len(medium_risk)}):
"""

        for p in medium_risk:
            summary += f"  - Port {p['port']}: {p['service']} (Risk Level: {p['risk_level']})\n"

        summary += """

RECOMMENDATIONS:
1. Close unnecessary services
2. Enable encryption (SSH instead of Telnet)
3. Use firewalls to restrict access
4. Keep systems updated

"""

        return summary


def main():
    """Main entry point for target analyzer."""
    analyzer = TargetAnalyzer()

    print("=" * 70)
    print("BRUTUS TARGET ANALYZER")
    print("=" * 70)
    print(f"\nAuthorized targets: {analyzer.authorized_targets}")

    # Scan localhost by default (safe)
    target = input("\nEnter target IP/host (localhost for self-check): ").strip() or 'localhost'

    if target in analyzer.authorized_targets:
        results = analyzer.scan_target(target)

        report = analyzer.generate_risk_report(results)
        print(report)

        # Save to file
        with open('target_analysis_report.txt', 'w') as f:
            f.write(report)

        print(f"\nReport saved to: target_analysis_report.txt")
    else:
        print("Target not authorized. Please add it via auth_gate.py first.")


if __name__ == "__main__":
    main()
