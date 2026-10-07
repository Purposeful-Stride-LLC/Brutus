#!/usr/bin/env python3
"""Sample output demo for Brutus Stage 2"""

def sample_output():
    print("\n" + "="*60)
    print("🐾 BRUTUS STAGE 2 - SAMPLE OUTPUT")
    print("="*60)

    # Sample assessment
    username = "admin"
    password = "1234"

    print(f"\n🔍 Analyzing: {username}@YOUR_SYSTEM")
    print(f"   Password strength check in progress...")

    print("\n⚠️  PASSWORD ALERT:")
    print(f"   Password '{password}' found in breach databases!")
    print(f"   Breach count: 8,500,000+ instances")
    print(f"   Likelihood of use: 78%")

    print("\n📊 USER ACCOUNT DETAILS:")
    print(f"   Username: {username}")
    print(f"   Common account type: Default system admin")
    print(f"   Individual risk score: 95%")

    combined_risk = (95 + 78) / 2  # 86.5%
    overall = "CRITICAL"

    print(f"\n⚠️  OVERALL COMPROMISE RISK: {overall}")
    print(f"   Combined risk score: {combined_risk:.1f}%")

    print("\n🛡️  DEFENSIVE RECOMMENDATIONS:")
    print("   • Disable 'admin' account immediately")
    print("   • Force password reset to strong random string")
    print("   • Enable multi-factor authentication")
    print("   • Monitor for compromised credentials")

    print("\n✅ BRUTUS CYBERPUPPY STAGE 2 OPERATIONAL!")
    print("="*60)


if __name__ == "__main__":
    sample_output()
