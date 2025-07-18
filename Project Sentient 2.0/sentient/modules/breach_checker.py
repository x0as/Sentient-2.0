import requests
import hashlib

def check_breach(email):
    """Check if email has been in data breaches - requires API key"""
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {"hibp-api-key": "YOUR_API_KEY", "user-agent": "sentient-cli"}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code == 404:
            return {"result": "No breach found."}
        else:
            return {"error": f"Status {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def breach_check_cli(email):
    """CLI interface for breach checking"""
    print(f"🔍 Checking if {email} has been involved in data breaches...")
    
    try:
        # Calculate SHA-1 hash of email (required by HaveIBeenPwned API)
        email_hash = hashlib.sha1(email.encode('utf-8')).hexdigest().upper()
        
        # For demo purposes - real implementation needs API key
        print("📊 Breach Check Results:")
        print("  • HaveIBeenPwned API: Requires paid subscription")
        print("  • BreachDirectory: Access limited") 
        print("  • DeHashed: Requires authentication")
        print(f"  • Email Hash (SHA-1): {email_hash[:8]}...")
        
        print("\n💡 To get real breach data:")
        print("  1. Sign up for HaveIBeenPwned API")
        print("  2. Add your API key to breach_checker.py")
        print("  3. Replace 'YOUR_API_KEY' with actual key")
        
        print(f"\n✅ Manual check: https://haveibeenpwned.com/account/{email}")
        
    except Exception as e:
        print(f"❌ Error checking breaches: {e}")

# Example usage:
# print(check_breach("test@example.com"))