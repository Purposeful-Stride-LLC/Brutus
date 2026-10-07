#!/usr/bin/env python3
"""
BRUTUS Authorization Gateway
Human-in-the-loop authorization checkpoint for all security testing.
Logs all authorizations for audit trail.
"""

import json
from datetime import datetime
from pathlib import Path


class AuthorizationGateway:
    """
    Manages user authorization for network testing activities.
    Ensures only authorized targets are tested.
    """

    def __init__(self, auth_file='configs/authorized_targets.txt', log_file='configs/auth_log.csv'):
        self.auth_file = Path(auth_file)
        self.log_file = Path(log_file)
        self.authorized_networks = set()

    def load_authorized_targets(self):
        """Load user-authorized network list from file."""
        if self.auth_file.exists():
            with open(self.auth_file, 'r') as f:
                for line in f:
                    target = line.strip()
                    if target and not target.startswith('#'):
                        self.authorized_networks.add(target.lower())

        return len(self.authorized_networks)

    def authorize_target(self, target_name, purpose='password_assessment'):
        """Add a new target to authorization list with human confirmation."""
        print("\n" + "="*70)
        print("BRUTUS AUTHORIZATION GATEWAY")
        print("="*70)
        print(f"\nTarget: {target_name}")
        print(f"Purpose: {purpose}")

        # Check if already authorized
        if target_name.lower() in self.authorized_networks:
            print("✓ Already authorized. Proceeding with testing.")
            return True

        # Display authorization prompt (simulated for now)
        print("\n*** AUTHORIZATION REQUIRED ***")
        print("By authorizing, you confirm:")
        print("  • You own or control this network/device")
        print("  • Testing is for security assessment purposes only")
        print("  • All findings will be documented and reported")
        print("  • No unauthorized access will be attempted")

        print("\nDo you authorize testing of this target? (y/n)")
        try:
            response = input().strip().lower()

            if response == 'y':
                # Add to authorized list
                with open(self.auth_file, 'a') as f:
                    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    log_entry = f"{target_name}|{purpose}|{timestamp}\n"
                    f.write(log_entry)

                self.authorized_networks.add(target_name.lower())
                print(f"\n✓ Authorization granted for: {target_name}")
                return True
            else:
                print("✗ Authorization declined. Target not added.")
                return False

        except KeyboardInterrupt:
            print("\nAuthorization cancelled.")
            return None

    def is_authorized(self, target):
        """Check if target is authorized for testing."""
        return target.lower() in self.authorized_networks

    def log_activity(self, target, action, status, details=''):
        """Log security activity to audit trail."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if self.log_file.exists():
            with open(self.log_file, 'a') as f:
                log_line = f"{target}|{action}|{status}|{details}\n"
                f.write(log_line)
        return True


def main():
    """Demo authorization gateway."""
    print("BRUTUS AUTHORIZATION GATEWAY - DEMO MODE")
    print("="*70)

    auth = AuthorizationGateway()
    target_count = auth.load_authorized_targets()

    print(f"\nCurrently authorized targets: {target_count}")
    if target_count > 0:
        with open(auth.auth_file, 'r') as f:
            print("\nAuthorized list:\n" + f.read())


if __name__ == "__main__":
    main()
