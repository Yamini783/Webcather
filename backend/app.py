
from flask import Flask, request, jsonify
from flask_cors import CORS
import numpy as np
import pickle
from feature_extraction import FeatureExtraction  # Import Feature Extraction
import logging

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS to handle requests from Chrome extension

# Enable logging for debugging
logging.basicConfig(level=logging.INFO)

# Load pre-trained ML model
model_path = "model.pkl"

gbc = None
try:
    with open(model_path, "rb") as file:
        gbc = pickle.load(file)
        logging.info("Model loaded successfully")
except Exception as e:
    logging.error(f"Error loading model: {e}")

@app.route("/", methods=["POST"])
def analyze_url():
    """API endpoint to analyze a URL for phishing detection."""
    try:
        data = request.get_json()

        # Validate JSON data
        if not data or "url" not in data:
            return jsonify({"error": "Invalid JSON data or missing 'url' key"}), 400

        url = data["url"].strip()
        if not url:
            return jsonify({"error": "No URL provided"}), 400

        if gbc is None:
            return jsonify({"error": "Model not loaded"}), 500

        # Extract features
        extractor = FeatureExtraction(url)
        features = extractor.getFeaturesList()
        
        if not features or len(features) != 30:
            return jsonify({"error": "Invalid feature extraction"}), 500

        features = np.array(features).reshape(1, -1)

        # Predict safety and get probabilities
        prediction = gbc.predict(features)[0]
        probabilities = gbc.predict_proba(features)[0]


        # Print model output in console
        logging.info(f"URL: {url}")
        logging.info(f"Extracted Features: {features}")
        logging.info(f"Prediction Probabilities: {probabilities}")
        
        # Ensure probabilities list has two values (for both classes)
        if len(probabilities) != 2:
            return jsonify({"error": "Model prediction error: invalid probabilities"}), 500

        # Extract probabilities and format them as percentages
        probability_safe = probabilities[1] * 100  # Safe URL
        probability_phishing = probabilities[0] * 100  # Phishing URL

        # Format response correctly
        if prediction == 1:
            result_text = f"Safe : {probability_safe:.2f}%"
        else:
            result_text = f"Unsafe : {probability_phishing:.2f}%"

        return jsonify({"url": url, "prediction": result_text})

    except Exception as e:
        logging.error(f"Error processing request: {e}")
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, port=5000)
