import socket
import whois
from urllib.parse import urlparse
from flask import Flask, request, render_template
from API import get_prediction  # Import your get_prediction function

app = Flask(__name__)

@app.route('/static/logo.png')
def serve_logo():
    return app.send_static_file('logo.png')

@app.route('/static/fake.png')
def serve_fake():
    return app.send_static_file('fake.png')

@app.route('/')
def index():
    return render_template('index.html')

def clean_url(url):
    """Helper function to clean and format URLs"""
    # Remove any whitespace
    url = url.strip()
    # Add protocol if missing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url

def get_ip_address(url):
    try:
        url = clean_url(url)
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc
        
        # Remove any port number if present
        if ':' in hostname:
            hostname = hostname.split(':')[0]
            
        print(f"Attempting to resolve hostname: {hostname}")  # Debug print
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except socket.gaierror as e:
        print(f"Socket error: {e}")  # Debug print
        return "Unable to resolve IP address"
    except Exception as e:
        print(f"Error in get_ip_address: {str(e)}")  # Debug print
        return "Error getting IP address"

def get_creation_date(url):
    try:
        url = clean_url(url)
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # Remove 'www.' if present and any port number
        if domain.startswith('www.'):
            domain = domain[4:]
        if ':' in domain:
            domain = domain.split(':')[0]
            
        print(f"Attempting WHOIS query for domain: {domain}")  # Debug print
        
        # Use whois() instead of query()
        w = whois.whois(domain)
        
        if w and w.creation_date:
            if isinstance(w.creation_date, list):
                return w.creation_date[0].strftime('%Y-%m-%d %H:%M:%S')
            elif w.creation_date:
                return w.creation_date.strftime('%Y-%m-%d %H:%M:%S')
            return "Creation date not available"
        return "WHOIS information not found"
    except Exception as e:
        print(f"Error in get_creation_date: {str(e)}")  # Debug print
        return "Unable to fetch creation date"

@app.route('/verify', methods=['POST'])
def verify_url():
    url = request.form.get('phishing_url')
    print(f"Received URL: {url}")  # Debug print
    
    # Clean the URL first
    cleaned_url = clean_url(url)
    print(f"Cleaned URL: {cleaned_url}")  # Debug print

    # Path to your trained model
    model_path = r"D:\OB\doc\BCA 2022\3rd Year\Autumn Term\CAP449_INDUSTRY TRAINING\project\PhishHunt-1.01v\Malicious_URL_Prediction.h5"

    try:
        prediction = get_prediction(cleaned_url, model_path)
        ip_address = get_ip_address(cleaned_url)
        creation_date = get_creation_date(cleaned_url)
        
        print(f"IP Address: {ip_address}")  # Debug print
        print(f"Creation Date: {creation_date}")  # Debug print
        
        return render_template("result.html", 
                             url=url,
                             ip_address=ip_address, 
                             creation_date=creation_date, 
                             result=prediction)
    except Exception as e:
        print(f"Error in verify_url: {str(e)}")  # Debug print
        return render_template("error.html", error=str(e))

if __name__ == '__main__':
    app.run(debug=True)
