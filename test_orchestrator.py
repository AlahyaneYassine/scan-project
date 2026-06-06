import sys
import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')

import django
django.setup()

from scanner.services.scan_orchestrator_service import ScanOrchestrator
from scanner.services.scan_validation_service import validate_scan_type, ValidationError

# Test 1: Validate CIDR target with allowed modules
print("Test 1: CIDR target validation")
try:
    target_type, scan_type = validate_scan_type("192.168.1.0/24", "host_discovery")
    print(f"✓ CIDR validation passed: {target_type.value}, {scan_type}")
except Exception as e:
    print(f"✗ Error: {e}")

# Test 2: Validate single IP with allowed modules
print("\nTest 2: Single IP target validation")
try:
    target_type, scan_type = validate_scan_type("192.168.1.100", "fast_scan")
    print(f"✓ Single IP validation passed: {target_type.value}, {scan_type}")
except Exception as e:
    print(f"✗ Error: {e}")

# Test 3: Orchestrator validation (should show errors for invalid CIDR module)
print("\nTest 3: Orchestrator validation")
try:
    orchestrator = ScanOrchestrator("192.168.1.0/24", ["host_discovery", "fast_scan"])
    result = orchestrator.execute()
    print(f"✓ Orchestrator executed")
    print(f"  - Target: {result['target']}")
    print(f"  - Target Type: {result['target_type']}")
    print(f"  - Modules executed: {list(result['modules'].keys())}")
    print(f"  - Errors: {result['errors']}")
    print(f"  - Warnings: {len(result['warnings'])} warnings")
except Exception as e:
    print(f"✗ Error: {e}")

# Test 4: Single IP orchestrator with multiple modules
print("\nTest 4: Single IP with multiple allowed modules")
try:
    orchestrator = ScanOrchestrator("192.168.1.100", ["fast_scan", "service_detection"])
    result = orchestrator.execute()
    print(f"✓ Orchestrator executed")
    print(f"  - Target: {result['target']}")
    print(f"  - Target Type: {result['target_type']}")
    print(f"  - Modules attempted: {list(result['modules'].keys())}")
    print(f"  - Module count: {len(result['modules'])}")
    print(f"  - Has warnings: {bool(result['warnings'])}")
except Exception as e:
    print(f"✗ Error: {e}")

print("\n✓ All orchestrator tests completed!")
