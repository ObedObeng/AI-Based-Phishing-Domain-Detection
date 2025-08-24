from flask import Flask, render_template, request, jsonify
from API import get_prediction

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('URL.html')

@app.route('/verify', methods=['POST'])
def verify_url():
    # Get the URL from the form
    url = request.form.get('phishing_url')

    # Path to your trained model
    model_path = r"D:\TechTitan\PhishHunt-1.01v\Malicious_URL_Prediction.h5"

    # Get the prediction
    prediction = get_prediction(url, model_path)

    # Return the result as JSON
    return jsonify({'prediction': prediction})

if __name__ == '__main__':
    app.run(debug=True)
