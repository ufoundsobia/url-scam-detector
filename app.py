from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import numpy as np
import re
import urllib.parse
from urllib.parse import urlparse
import tldextract
import os

app = Flask(__name__)
CORS(app)  # Enable CORS for React app

# Load trained model
model = joblib.load('url_scam_detector.pkl')
label_encoder = joblib.load('label_encoder.pkl')

def extract_url_features(url):
    """
    Extract features from URL for scam detection
    Same function as used in training
    """
    features = []
    
    try:
        parsed = urlparse(url)
        domain_info = tldextract.extract(url)
        
        # Feature 1-20 (same as training)
        features.append(len(url))
        features.append(url.count('.'))
        features.append(url.count('-'))
        features.append(url.count('_'))
        features.append(url.count('/'))
        features.append(url.count('?'))
        features.append(url.count('='))
        features.append(url.count('@'))
        features.append(url.count('&'))
        features.append(url.count('%'))
        features.append(1 if parsed.scheme == 'https' else 0)
        
        ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        features.append(1 if ip_pattern.search(url) else 0)
        
        features.append(len(domain_info.subdomain.split('.')) if domain_info.subdomain else 0)
        features.append(len(domain_info.domain) if domain_info.domain else 0)
        
        suspicious_keywords = ['login', 'signin', 'bank', 'secure', 'account', 
                             'update', 'verify', 'confirm', 'suspended', 'blocked',
                             'paypal', 'amazon', 'microsoft', 'apple', 'google']
        features.append(sum(1 for keyword in suspicious_keywords if keyword in url.lower()))
        
        features.append(1 if parsed.port else 0)
        
        shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'short.link', 'ow.ly']
        features.append(1 if any(shortener in url.lower() for shortener in shorteners) else 0)
        
        features.append(len(re.findall(r'\d', url)))
        features.append(len(re.findall(r'\d', url)) / len(url) if len(url) > 0 else 0)
        
        unusual_tlds = ['.tk', '.ml', '.ga', '.cf', '.click', '.download', '.link']
        features.append(1 if any(tld in url.lower() for tld in unusual_tlds) else 0)
        
    except Exception as e:
        features = [0] * 20
    
    return features

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        url = data.get('url', '')
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        # Extract features
        features = extract_url_features(url)
        features_array = np.array([features])
        
        # Make prediction
        prediction = model.predict(features_array)[0]
        confidence = model.predict_proba(features_array)[0]
        
        # Convert prediction to human readable
        is_malicious = prediction == 1
        result = "Suspicious/Scam" if is_malicious else "Safe"
        confidence_score = float(max(confidence))
        
        return jsonify({
            'url': url,
            'result': result,
            'is_malicious': bool(is_malicious),
            'confidence': round(confidence_score * 100, 2),
            'details': {
                'url_length': features[0],
                'has_suspicious_keywords': features[14] > 0,
                'is_https': bool(features[10]),
                'has_ip_address': bool(features[11])
            }
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy', 'message': 'URL Scam Detector API is running'})

@app.route('/', methods=['GET'])
def home():
    return jsonify({
        'message': 'URL Scam Detection API',
        'endpoints': {
            'POST /predict': 'Analyze URL for scam detection',
            'GET /health': 'Check API health'
        }
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)