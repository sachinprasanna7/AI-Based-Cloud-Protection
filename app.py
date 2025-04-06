import joblib
import numpy as np
from flask import Flask, request, jsonify

rfe_selector = joblib.load('Models/rfe_selector.pkl')
gb_model = joblib.load('Models/gradient_boosting.pkl')

attack_mapping = {
    1: 'MITM', 2: 'Fingerprinting', 3: 'Ransomware', 4: 'Uploading',
    5: 'SQL_injection', 6: 'DDoS_HTTP', 7: 'DDoS_TCP', 8: 'Password',
    9: 'Port_Scanning', 10: 'Vulnerability_scanner', 11: 'Backdoor',
    12: 'XSS', 13: 'Normal', 14: 'DDoS_UDP', 15: 'DDoS_ICMP'
}

app = Flask(__name__)

@app.route('/predict', methods=['POST'])
def predict_attack():
    try:
        data = request.get_json()
        features = data.get("features", [])

        if not features or len(features) != 32:
            return jsonify({"error": "Invalid or missing input. Expecting 32 features."}), 400

        # Convert to NumPy array and reshape to (1, 34)
        X_new = np.array(features, dtype=np.float64).reshape(1, -1)

        # Apply RFE to select features
        X_selected = rfe_selector.transform(X_new)

        # Predict attack type
        prediction = int(gb_model.predict(X_selected)[0])
        attack_name = attack_mapping.get(prediction, "Unknown")

        return jsonify({
            "attack_type": attack_name
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)