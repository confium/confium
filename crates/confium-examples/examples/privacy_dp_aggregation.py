#!/usr/bin/env python3
"""Differential privacy aggregation in Python."""

from confium.privacy import dp_query

true_count = 1234
epsilon = 0.5

# Each call adds fresh Laplace noise
for _ in range(5):
    noisy = dp_query(true_count, sensitivity=1, epsilon=epsilon)
    print(f"True: {true_count} → Published: {noisy:.2f}")

print("✅ DP aggregation demo complete.")
