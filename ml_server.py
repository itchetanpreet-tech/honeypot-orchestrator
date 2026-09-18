#!/usr/bin/env python3
"""
ML Model as a Service - Flask microservice
"""
from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import numpy as np
import os

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Load model
model_path = 'ml/models/attack_classifier.joblib'
if not os.path.exists(model_path):
    print(f"[!] Model not found at {model_path}")
    print("[!] Run classifier.py first!")
    exit(1)

model_data = joblib.load(model_path)
clf = model_data['model']
le = model_data['label_encoder']
features = model_data['feature_cols']

print(f"[+] ML Server started!")
print(f"[+] Features: {len(features)}")
print(f"[+] Classes: {le.classes_.tolist()}")

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.json
        feature_values = data.get('features', [])
        
        if len(feature_values) != len(features):
            return jsonify({
                'error': f'Expected {len(features)} features, got {len(feature_values)}'
            }), 400
        
        X = np.array([feature_values])
        pred = clf.predict(X)
        attack_type = le.inverse_transform(pred)[0]
        
        # Get probability
        probs = clf.predict_proba(X)[0]
        confidence = float(max(probs))
        
        return jsonify({
            'attack_type': attack_type,
            'confidence': round(confidence, 4),
            'features_used': features
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'healthy',
        'model_loaded': True,
        'classes': le.classes_.tolist(),
        'features': features
    })

@app.route('/', methods=['GET'])
def home():
    return jsonify({
        'service': 'Honeypot Orchestrator ML Model',
        'status': 'running',
        'endpoints': ['/predict', '/health', '/']
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=False)
