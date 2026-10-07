#!/usr/bin/env python3
"""
BRUTUS WiFi/Bluetooth Survey Module
Lists all available wireless networks with signal strength ranking.
Safe passive reconnaissance — NO cracking attempts.
"""

import subprocess
import json
from datetime import datetime


def survey_wifi_networks():
    """Use netsh to list WiFi networks and signal strength."""
    print("=" * 70)
    print("BRUTUS WiFi/Bluetooth Network Survey")
    print(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

    try:
        # Windows netsh command for network list
        result = subprocess.run(
            ['netsh', 'wlan', 'show', 'networks'],
            capture_output=True,
            text=True,
            timeout=10
        )

        networks = []
        lines = result.stdout.split('\n')

        for line in lines:
            # Parse network info (format varies by Windows version)
            if 'SSID' in line and 'Network' in line:
                parts = line.strip().split()
                if len(parts) >= 4:
                    ssid = parts[2]  # Usually SSID field is index 2
                    signal = parts[-1]  # Last field is typically signal bar count

                    try:
                        # Convert bar count to approximate dBm
                        bars = int(''.join(filter(str.isdigit, signal)) or '0')
                        dbm_estimate = -50 - (bars * 4)  # Rough estimation

                        networks.append({
                            'ssid': ssid,
                            'signal_bars': bars,
                            'signal_dbm_estimate': dbm_estimate,
                            'security': parts[-2] if len(parts) > 3 else 'Unknown',
                            'frequency': None
                        })
                    except ValueError:
                        pass

        # Sort by signal strength (descending)
        networks.sort(key=lambda x: x['signal_dbm_estimate'], reverse=True)

        # Display results
        print(f"\n{'='*70}")
        print(f"DISCOVERED NETWORKS ({len(networks)} total)")
        print(f"{'='*70}\n")

        print(f"{'Rank':<5} {'SSID':<35} {'Signal (dBm) ':<12} {'Security'}")
        print("-" * 70)

        for i, net in enumerate(networks[:10], 1):  # Show top 10
            bars = net['signal_bars']
            signal_text = "📶" * bars if bars > 0 else "N/A"
            print(f"{i:<5} {net['ssid'][:34]:<35} {net['signal_dbm_estimate']:<12} {net['security']}")

        # Bluetooth network connections
        print(f"\n{'='*70}")
        print("Bluetooth Network Connections:")
        print("-" * 70)

        bt_result = subprocess.run(
            ['netsh', 'lansetup', 'show'],
            capture_output=True,
            text=True,
            timeout=10
        )

        bt_lines = bt_result.stdout.split('\n')
        for line in bt_lines:
            if 'Bluetooth' in line and ('Network' in line or 'Paired' in line):
                print(f"  • {line.strip()}")

        # Save survey results to file
        with open('wifi_networks_survey.json', 'w') as f:
            json.dump(networks, f, indent=2)

        print(f"\nSurvey saved to: wifi_networks_survey.json")
        print("=" * 70)

        return networks

    except subprocess.TimeoutExpired:
        print("Error: Network scan timed out.")
        return []
    except Exception as e:
        print(f"Survey error: {e}")
        return []


def main():
    """Run the WiFi survey and display results."""
    surveys = survey_wifi_networks()

    if surveys:
        print("\n[BRUTUS SURVEY COMPLETE]")
        print("Review authorized_targets.txt to add networks for testing.")
        print("Then run: python target_analyzer.py")
    else:
        print("[SURVEY INCOMPLETE - NO NETWORKS DETECTED]")


if __name__ == "__main__":
    main()
