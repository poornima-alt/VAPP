
from risk_engine import (
    calculate_risk,
    generate_explanation,
    generate_recommendation
)

print("========== VAPP RISK ENGINE TEST ==========")

# Test 1: Normal activity
normal_event = {
    "failed_attempts": 0,
    "unique_ports": 1,
    "event_rate": 1,
    "suspicious_keyword": 0
}

normal_result = calculate_risk(normal_event, "Normal", 96)

print("\nTest 1 - Normal activity:")
print(normal_result)

# Test 2: Brute force
brute_event = {
    "failed_attempts": 10,
    "unique_ports": 1,
    "event_rate": 15,
    "suspicious_keyword": 1
}

brute_result = calculate_risk(brute_event, "Brute Force", 100)

print("\nTest 2 - Brute Force:")
print(brute_result)

# Test 3: Port scan
port_event = {
    "failed_attempts": 0,
    "unique_ports": 15,
    "event_rate": 30,
    "suspicious_keyword": 1
}

port_result = calculate_risk(port_event, "Port Scan", 98)

print("\nTest 3 - Port Scan:")
print(port_result)

# Test 4: Explanation
explanation = generate_explanation(
    brute_event, "Brute Force", brute_result["risk_level"]
)

print("\nTest 4 - Threat explanation:")
print(explanation)

# Test 5: Defensive recommendation
recommendation = generate_recommendation(
    "Brute Force", brute_result["risk_level"]
)

print("\nTest 5 - Defensive recommendation:")
print(recommendation)

# Test 6: Invalid event
print("\nTest 6 - Invalid input:")

try:
    calculate_risk(
        {"failed_attempts": -5},
        "Brute Force",
        90
    )
    print("FAILED: Invalid input was accepted.")
except ValueError as error:
    print("PASSED: Invalid input rejected:", error)

# Test 7: Invalid confidence
print("\nTest 7 - Invalid confidence:")

try:
    calculate_risk(normal_event, "Normal", 150)
    print("FAILED: Invalid confidence was accepted.")
except ValueError as error:
    print("PASSED: Invalid confidence rejected:", error)

print("\n========== TESTS COMPLETED ==========")
