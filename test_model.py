#!/usr/bin/env python3
"""
Test the trained ML model
"""
import joblib
import numpy as np
import os

# Model load karo
model_path = 'ml/models/attack_classifier.joblib'
if not os.path.exists(model_path):
    print(f"[!] Model not found at {model_path}")
    exit(1)

print("[+] Loading model from", model_path)
model_data = joblib.load(model_path)

clf = model_data['model']
le = model_data['label_encoder']
features = model_data['feature_cols']

print(f"[+] Model loaded successfully!")
print(f"[+] Features: {features}")
print(f"[+] Classes: {le.classes_}")

# Example prediction
print("\n[+] Testing with sample data...")
X_sample = np.array([[
    5,   # request_count
    3,   # failed_attempts
    150, # payload_length
    0,   # is_ssh
    1,   # is_http
    0,   # is_db
    0,   # has_login
    1,   # has_sqli_pattern
    0,   # has_xss_pattern
    0    # has_cmd_pattern
]])

pred = clf.predict(X_sample)
attack_type = le.inverse_transform(pred)
print(f"[+] Prediction: {attack_type[0]}")

# Model accuracy (if available)
print("\n[+] Model info:")
print(f"    Number of trees: {clf.n_estimators}")
print(f"    Max depth: {clf.max_depth}")
print(f"    Feature count: {len(features)}")
