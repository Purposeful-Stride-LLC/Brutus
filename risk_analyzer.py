#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Brutus User Account Risk Analyzer - Stage 2 (Educational Demo)
Pairs usernames with password breach data to assess account risk
Defensive tool for auditing YOUR OWN systems only!
Requires explicit authorization before scanning any target!
"""

import json
from datetime import datetime


# Common usernames database (defensive analysis only)
COMMON_USERS = {
    'admin': {'risk': 95, 'reason': 'Default system admin account'},
    'administrator': {'risk': 85, 'reason': 'Windows default admin'},
    'root': {'risk': 90, 'reason': 'Unix/Linux superuser'},
    'user': {'risk': 60, 'reason': 'Generic user account'},
    'test': {'risk': 40, 'reason': 'Test/dev account often forgotten'},
    'mysql': {'risk': 80, 'reason': 'Database service account'},
    'postgres': {'risk': 75, 'reason': 'Database service account'},
    'guest': {'risk': 70, 'reason': 'Guest accounts should be disabled'},
    'support': {'risk': 55, 'reason': 'IT support shared account'},
    'oracle': {'risk': 65, 'reason': 'Oracle database account'},
}

# Common password patterns from rainbow table
WEAK_PASSWORDS = {
    'password': {'breaches': 34700001, 'likelihood': 99, 'recommendation': 'Use uppercase + symbols + longer length'},
    'admin': {'breaches': 14200000, 'likelihood': 85, 'recommendation': 'Same as above'},
    '1234': {'breaches': 8500000, 'likelihood': 78, 'recommendation': 'Never use sequential numbers'},
    '123456': {'breaches': 28800000, 'likelihood': 96, 'recommendation': 'Use random character mix'},
    'qwerty': {'breaches': 15400000, 'likelihood': 87, 'recommendation': 'Avoid keyboard patterns'},
}


def assess_user_password_combination(username, password):
    """Assess the risk of a username/password combination."""

    print("\n" + "="*60)
    print(f"🔐 USER ACCOUNT RISK ASSESSMENT")
    print("="*60)

    # Check if password is in weak database
    if password.lower() in WEAK_PASSWORDS:
        weak_info = WEAK_PASSWORDS[password.lower()]
        print(f"\n⚠️  PASSWORD ALERT:")
        print(f"   Password '{password}' appears in breach databases!")
        print(f"   Breach count: {weak_info['breaches']:,}")
        print(f"   Likelihood score: {weak_info['likelihood']}%")
        print(f"   Recommendation: {weak_info['recommendation']}")

        # Check username risk
        if username.lower() in COMMON_USERS:
            user_info = COMMON_USERS[username.lower()]
            combined_risk = (user_info['risk'] + weak_info['likelihood']) / 2

            print(f"\n📊 USER ACCOUNT DETAILS:")
            print(f"   Username: {username}")
            print(f"   Reason for inclusion: {user_info['reason']}")
            print(f"   Individual risk score: {user_info['risk']}%")

            overall_risk = "CRITICAL" if combined_risk > 80 else \
                           "HIGH" if combined_risk > 70 else \
                           "MODERATE" if combined_risk > 50 else "LOW"

            print(f"\n⚠️  OVERALL COMPROMISE RISK: {overall_risk}")
            print(f"   Combined risk score: {(user_info['risk'] + weak_info['likelihood']) / 2:.1f}%")

        return {
            'status': 'WEAK',
            'combined_risk': (COMMON_USERS.get(username.lower(), {}).get('risk', 50) +
                            WEAK_PASSWORDS.get(password.lower(), {}).get('likelihood', 50)) / 2,
            'password_breach_count': weak_info['breaches']
        }

    else:
        print(f"\n✅ PASSWORD CHECK:")
        print(f"   Password '{password}' not found in common breach list")
        print(f"   (May still be weak based on complexity)")

        # Check username risk
        if username.lower() in COMMON_USERS:
            user_info = COMMON_USERS[username.lower()]
            print(f"\n📊 USER ACCOUNT DETAILS:")
            print(f"   Username: {username}")
            print(f"   Reason for inclusion: {user_info['reason']}")
            print(f"   Risk score: {user_info['risk']}%")

            print(f"\nℹ️  OVERALL ASSESSMENT:")
            print(f"   Password not in breach list, but username is commonly exploited")

        return {
            'status': 'UNVERIFIED',
            'combined_risk': COMMON_USERS.get(username.lower(), {}).get('risk', 50),
            'password_breach_count': 0
        }


def generate_security_audit_report(target='local_system'):
    """Generate a sample security audit report template."""

    print("\n" + "="*60)
    print("📋 SECURITY AUDIT REPORT - TEMPLATE")
    print("="*60)

    report = {
        'audit_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'target': target,
        'auditor': 'Brutus Cyberpuppy v0.2 (Educational)',
        'scope': ['Username analysis', 'Password breach checking', 'Weak pattern detection'],
        'findings': [],
        'recommendations': [
            'Disable default accounts (admin, guest, support)',
            'Enforce password complexity requirements',
            'Implement multi-factor authentication',
            'Audit for service accounts with weak credentials'
        ]
    }

    print(f"\n📅 Audit Date: {report['audit_date']}")
    print(f"🎯 Target: {report['target']}")
    print(f"👤 Auditor: {report['auditor']}")

    print("\n🔍 Scope:")
    for item in report['scope']:
        print(f"   • {item}")

    return report


def main():
    """Run Brutus risk analyzer demo."""

    print("\n" + "="*60)
    print("⚠️  EDUCATIONAL DEMO - DEFENSIVE USE ONLY")
    print("="*60)

    print("\n📚 This tool demonstrates:")
    print("   • Password breach database checking")
    print("   • Username risk analysis")
    print("   • Combined account risk assessment")
    print("   • Security audit report templates")

    print("\n⚠️  AUTHORIZATION REQUIRED:")
    print("   Before analyzing real systems, you MUST have:")
    print("   - Explicit permission from the system owner")
    print("   - Understanding of legal implications")
    print("   - Authorization for scanning activities")

    # Demo: Assess a sample combination (educational)
    username = input("\nEnter username to analyze (or 'quit'): ").strip()
    password = input("Enter password to check (or type your own): ").strip()

    if username.lower() != 'quit':
        result = assess_user_password_combination(username, password)

        print(f"\n\n📊 RESULTS:")
        print(f"   Status: {result['status']}")
        print(f"   Combined Risk: {result['combined_risk']:.1f}%")
        if result['password_breach_count'] > 0:
            print(f"   Breach count: {result['password_breach_count']:,}")


if __name__ == "__main__":
    main()
