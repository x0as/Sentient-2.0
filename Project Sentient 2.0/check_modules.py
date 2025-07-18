#!/usr/bin/env python3

import sys
import os

# Add the sentient package to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'sentient'))

modules_to_check = [
    'modules.traffic_sender',
    'modules.real_traffic',
    'modules.file_analysis',
    'modules.Phone_Lookup',
    'modules.Email_Lookup', 
    'modules.Email_Tracker',
    'modules.website_scanner',
    'modules.whois_lookup',
    'modules.subdomain_enum',
    'modules.port_scanner',
    'modules.dir_bruteforce',
    'modules.hash_tools',
    'modules.ssl_checker',
    'modules.dns_tools',
    'modules.email_spoof_test',
    'modules.log_analyzer',
    'modules.virustotal_scan',
    'modules.breach_checker',
    'modules.cve_search',
    'modules.geoip_lookup',
    'modules.image_metadata',
    'modules.jwt_analyzer',
    'modules.packet_analyzer',
    'modules.password_strength',
    'modules.pdf_analyzer',
    'modules.reverse_ip',
    'modules.subdomain_takeover',
    'modules.url_expander',
    'modules.username_checker'
]

print("🔍 Checking Sentient AI Module Availability...")
print("=" * 50)

available_modules = []
missing_modules = []

for module_name in modules_to_check:
    try:
        __import__(module_name)
        available_modules.append(module_name)
        print(f"✅ {module_name}")
    except ImportError as e:
        missing_modules.append(module_name)
        print(f"❌ {module_name} - {e}")
    except Exception as e:
        missing_modules.append(module_name)
        print(f"⚠️  {module_name} - Error: {e}")

print("\n" + "=" * 50)
print(f"📊 Summary:")
print(f"✅ Available Modules: {len(available_modules)}")
print(f"❌ Missing/Error Modules: {len(missing_modules)}")
print(f"📈 Module Coverage: {len(available_modules)}/{len(modules_to_check)} ({len(available_modules)/len(modules_to_check)*100:.1f}%)")

if missing_modules:
    print(f"\n🚨 Missing modules that need attention:")
    for module in missing_modules:
        print(f"   - {module}")
else:
    print(f"\n🎉 All {len(available_modules)} modules are available! Sentient AI is fully operational.")

print(f"\n🎯 Ready for tomorrow's presentation!")
