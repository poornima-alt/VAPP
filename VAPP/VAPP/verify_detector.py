
from detector import detector

print("========== VAPP DETECTOR TEST ==========")

# Test 1: Normal activity
normal_event = {
    "failed_attempts": 0,
    "unique_ports": 1,
    "event_rate": 1,
    "suspicious_keyword": 0,
    "unusual_port": 0
}

print("\nTest 1 - Normal activity:")
print(detector.analyze(normal_event))

# Test 2: Brute force pattern
brute_force_event = {
    "failed_attempts": 10,
    "unique_ports": 1,
    "event_rate": 15,
    "suspicious_keyword": 1,
    "unusual_port": 22
}

print("\nTest 2 - Brute force pattern:")
print(detector.analyze(brute_force_event))

# Test 3: Port scan pattern
port_scan_event = {
    "failed_attempts": 0,
    "unique_ports": 15,
    "event_rate": 30,
    "suspicious_keyword": 1,
    "unusual_port": 0
}

print("\nTest 3 - Port scan pattern:")
print(detector.analyze(port_scan_event))

# Test 4: Invalid input
print("\nTest 4 - Invalid input:")

try:
    detector.analyze({"failed_attempts": -5})
    print("FAILED: Invalid input was accepted.")
except ValueError as error:
    print("PASSED: Invalid input rejected:", error)

# Test 5: Model evaluation
print("\nTest 5 - Model evaluation:")
detector.evaluate_model()

print("\n========== TESTS COMPLETED ==========")
