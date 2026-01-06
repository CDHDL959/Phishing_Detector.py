import re
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix, precision_score, recall_score
import requests
import pickle
import os
from flask import Flask, render_template_string, request, jsonify
from datetime import datetime
import zipfile
import io

# ============================================================================
# DATA LOADING
# ============================================================================

class PhishingDatasetLoader:
    """Load phishing datasets from open sources"""
    
    @staticmethod
    def load_tranco_top_sites(limit=1000):
        """Load legitimate domains from Tranco Top Sites list"""
        print("Fetching Tranco top sites list...")
        
        try:
            url = "https://tranco-list.eu/top-1m.csv.zip"
            response = requests.get(url, timeout=60)
            response.raise_for_status()
            
            with zipfile.ZipFile(io.BytesIO(response.content)) as z:
                csv_filename = z.namelist()[0]
                with z.open(csv_filename) as f:
                    lines = f.read().decode('utf-8').strip().split('\n')[:limit]
                    
            legitimate_data = []
            for line in lines:
                rank, domain = line.split(',')
                paths = ['', '/login', '/account', '/about', '/search?q=test']
                for path in paths:
                    legitimate_data.append({
                        'url': f'https://{domain}{path}',
                        'source': 'tranco',
                        'label': 0
                    })
                    legitimate_data.append({
                        'url': f'https://www.{domain}{path}',
                        'source': 'tranco',
                        'label': 0
                    })
            
            df = pd.DataFrame(legitimate_data)
            print(f"✓ Loaded {len(df)} legitimate URLs from Tranco")
            return df
            
        except Exception as e:
            print(f"✗ Error loading Tranco: {e}")
            return pd.DataFrame()
    
    @staticmethod
    def load_openphish(limit=1000):
        """Load phishing URLs from OpenPhish"""
        print("Fetching OpenPhish data...")
        
        try:
            url = "https://openphish.com/feed.txt"
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            urls = response.text.strip().split('\n')[:limit]
            
            phishing_data = [{
                'url': url.strip(),
                'source': 'openphish',
                'label': 1
            } for url in urls if url.strip()]
            
            df = pd.DataFrame(phishing_data)
            print(f"✓ Loaded {len(df)} phishing URLs from OpenPhish")
            return df
        except Exception as e:
            print(f"✗ Error loading OpenPhish: {e}")
            return pd.DataFrame()
    
    @staticmethod
    def load_phishtank(limit=1000):
        """Load verified phishing URLs from PhishTank"""
        print("Fetching PhishTank data...")
        
        try:
            url = "http://data.phishtank.com/data/online-valid.json"
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            phishing_data = [{
                'url': item.get('url', ''),
                'label': 1
            } for item in data[:limit]]
            
            df = pd.DataFrame(phishing_data)
            print(f"✓ Loaded {len(df)} phishing URLs from PhishTank")
            return df
        except Exception as e:
            print(f"✗ Error loading PhishTank: {e}")
            return pd.DataFrame()
    
    @staticmethod
    def load_legitimate_urls(limit=500):
        """Fallback: Generate legitimate URL patterns"""
        print("Generating legitimate URL samples...")
        
        legitimate_domains = [
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'facebook.com', 'github.com', 'stackoverflow.com', 'wikipedia.org',
            'reddit.com', 'youtube.com', 'netflix.com', 'spotify.com',
            'paypal.com', 'ebay.com', 'walmart.com', 'cnn.com'
        ]
        
        legitimate_data = []
        paths = ['', '/about', '/login', '/search?q=test', '/account/settings']
        
        for domain in legitimate_domains:
            for path in paths:
                protocol = 'https://' if hash(domain) % 2 == 0 else 'http://'
                legitimate_data.append({
                    'url': f'{protocol}{domain}{path}',
                    'label': 0
                })
        
        df = pd.DataFrame(legitimate_data[:limit])
        print(f"✓ Generated {len(df)} legitimate URL samples")
        return df


# ============================================================================
# FEATURE EXTRACTION
# ============================================================================

class URLFeatureExtractor:
    """Extract features from URLs for ML classification"""
    
    @staticmethod
    def extract_features(url):
        """Extract comprehensive features from URL"""
        features = {}
        
        try:
            features['url_length'] = len(url)
            parts = url.split('/')
            domain = parts[2] if len(parts) > 2 else url
            
            features['domain_length'] = len(domain)
            features['path_length'] = len('/'.join(parts[3:])) if len(parts) > 3 else 0
            features['dot_count'] = url.count('.')
            features['dash_count'] = url.count('-')
            features['underscore_count'] = url.count('_')
            features['slash_count'] = url.count('/')
            features['digit_count'] = sum(c.isdigit() for c in url)
            features['digit_ratio'] = features['digit_count'] / len(url) if len(url) > 0 else 0
            features['is_https'] = 1 if url.startswith('https://') else 0
            features['has_ip'] = 1 if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', url) else 0
            features['subdomain_count'] = domain.count('.') - 1 if '.' in domain else 0
            
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz']
            features['has_suspicious_tld'] = 1 if any(url.endswith(tld) for tld in suspicious_tlds) else 0
            
            suspicious_keywords = ['verify-account', 'update-billing', 'account-suspended']
            features['suspicious_word_count'] = sum(1 for kw in suspicious_keywords if kw in url.lower())
            
            features['has_url_encoding'] = 1 if '%' in url else 0
            features['has_port'] = 1 if re.search(r':\d+', url) else 0
            
        except Exception as e:
            return {key: 0 for key in range(15)}
        
        return features


# ============================================================================
# MACHINE LEARNING MODEL
# ============================================================================

class PhishingDetectorML:
    """Random Forest based phishing detector"""
    
    def __init__(self):
        self.vectorizer = TfidfVectorizer(max_features=1000, ngram_range=(2, 4), min_df=2)
        self.model = RandomForestClassifier(
            n_estimators=150,
            max_depth=15,
            min_samples_split=10,
            min_samples_leaf=5,
            random_state=42,
            n_jobs=-1,
            class_weight='balanced'
        )
        self.feature_extractor = URLFeatureExtractor()
        self.is_trained = False
    
    def train_from_datasets(self, phishing_limit=500, legitimate_limit=1000, 
                           use_top_sites=True):
        """Train model using online datasets"""
        loader = PhishingDatasetLoader()
        all_data = []
        
        # Load phishing datasets
        openphish_df = loader.load_openphish(limit=phishing_limit // 2)
        if not openphish_df.empty:
            all_data.append(openphish_df[['url', 'label']])
        
        phishtank_df = loader.load_phishtank(limit=phishing_limit // 2)
        if not phishtank_df.empty:
            all_data.append(phishtank_df[['url', 'label']])
        
        # Load legitimate URLs from top sites
        if use_top_sites:
            print("\n--- Loading Real Top Sites for Training ---")
            tranco_df = loader.load_tranco_top_sites(limit=legitimate_limit)
            if not tranco_df.empty:
                all_data.append(tranco_df[['url', 'label']])
        
        # Fallback to generated URLs if needed
        if not any(df['label'].eq(0).any() for df in all_data if 'label' in df.columns):
            print("\nFalling back to generated legitimate URLs...")
            legitimate_df = loader.load_legitimate_urls(limit=legitimate_limit)
            if not legitimate_df.empty:
                all_data.append(legitimate_df[['url', 'label']])
        
        if not all_data:
            raise ValueError("Failed to load datasets")
        
        # Combine data
        combined_df = pd.concat(all_data, ignore_index=True)
        phishing_count = sum(combined_df['label'] == 1)
        legitimate_count = sum(combined_df['label'] == 0)
        
        print(f"\n{'='*60}")
        print(f"Dataset: {len(combined_df)} samples")
        print(f"Phishing: {phishing_count} ({phishing_count/len(combined_df)*100:.1f}%)")
        print(f"Legitimate: {legitimate_count} ({legitimate_count/len(combined_df)*100:.1f}%)")
        print(f"{'='*60}\n")
        
        return self.train(combined_df['url'].tolist(), combined_df['label'].tolist())
    
    def train(self, urls, labels):
        """Train the Random Forest model"""
        print("Training Random Forest model...")
        
        X_text = self.vectorizer.fit_transform(urls)
        
        url_features = []
        for url in urls:
            features = self.feature_extractor.extract_features(url)
            url_features.append(list(features.values()))
        
        X_url_features = np.array(url_features)
        X = np.hstack([X_text.toarray(), X_url_features])
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, labels, test_size=0.2, random_state=42, stratify=labels
        )
        
        self.model.fit(X_train, y_train)
        self.is_trained = True
        
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, pos_label=1)
        recall = recall_score(y_test, y_pred, pos_label=1)
        
        print(f"\n{'='*60}")
        print("TRAINING COMPLETE!")
        print(f"{'='*60}")
        print(f"Accuracy: {accuracy:.2%}")
        print(f"Precision (Phishing): {precision:.2%}")
        print(f"Recall (Phishing): {recall:.2%}")
        print(f"\nClassification Report:")
        print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
        
        cm = confusion_matrix(y_test, y_pred)
        print(f"\nConfusion Matrix:")
        print(f"                 Predicted")
        print(f"               Legit  Phish")
        print(f"Actual Legit    {cm[0][0]:4d}  {cm[0][1]:4d}")
        print(f"       Phish    {cm[1][0]:4d}  {cm[1][1]:4d}")
        
        fpr = cm[0][1] / (cm[0][0] + cm[0][1]) if (cm[0][0] + cm[0][1]) > 0 else 0
        print(f"\nFalse Positive Rate: {fpr:.2%}")
        
        return accuracy
    
    def predict(self, url):
        """Predict if URL is phishing"""
        if not self.is_trained:
            raise ValueError("Model must be trained first!")
        
        X_text = self.vectorizer.transform([url])
        features = self.feature_extractor.extract_features(url)
        X_features = np.array([list(features.values())])
        X = np.hstack([X_text.toarray(), X_features])
        
        probabilities = self.model.predict_proba(X)[0]
        is_phishing = probabilities[1] > 0.6
        
        return {
            'url': url,
            'is_phishing': bool(is_phishing),
            'confidence': float(probabilities[1] if is_phishing else probabilities[0]),
            'phishing_probability': float(probabilities[1]),
            'legitimate_probability': float(probabilities[0]),
            'risk_level': 'HIGH' if probabilities[1] > 0.8 else 'MEDIUM' if probabilities[1] > 0.6 else 'LOW',
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
    
    def save_model(self, filepath='phishing_detector.pkl'):
        """Save trained model"""
        with open(filepath, 'wb') as f:
            pickle.dump({
                'model': self.model,
                'vectorizer': self.vectorizer,
                'feature_extractor': self.feature_extractor
            }, f)
        print(f"Model saved to {filepath}")
    
    def load_model(self, filepath='phishing_detector.pkl'):
        """Load trained model"""
        with open(filepath, 'rb') as f:
            data = pickle.load(f)
            self.model = data['model']
            self.vectorizer = data['vectorizer']
            self.feature_extractor = data['feature_extractor']
            self.is_trained = True
        print(f"Model loaded from {filepath}")


# ============================================================================
# FLASK WEB APPLICATION
# ============================================================================

app = Flask(__name__)
detector = PhishingDetectorML()

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Phishing URL Detector</title>
    <style>
        body { font-family: Arial; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 20px; }
        .container { max-width: 800px; margin: 0 auto; background: white; border-radius: 20px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px; text-align: center; border-radius: 20px 20px 0 0; }
        .content { padding: 40px; }
        input[type="text"] { width: 100%; padding: 15px; border: 2px solid #e0e0e0; border-radius: 10px; font-size: 16px; }
        button { width: 100%; padding: 15px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; border-radius: 10px; font-size: 18px; cursor: pointer; margin-top: 10px; }
        .result { margin-top: 30px; padding: 20px; border-radius: 10px; display: none; }
        .result.safe { background: #d4edda; border: 2px solid #28a745; }
        .result.danger { background: #f8d7da; border: 2px solid #dc3545; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Phishing URL Detector</h1>
            <p>Machine Learning Protection</p>
        </div>
        <div class="content">
            <form id="urlForm">
                <input type="text" id="url" placeholder="Enter URL to check" required>
                <button type="submit">Analyze URL</button>
            </form>
            <div class="result" id="result"></div>
        </div>
    </div>
    <script>
        document.getElementById('urlForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const url = document.getElementById('url').value;
            const response = await fetch('/predict', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({url: url})
            });
            const data = await response.json();
            const resultDiv = document.getElementById('result');
            resultDiv.className = data.is_phishing ? 'result danger' : 'result safe';
            resultDiv.innerHTML = `
                <h2>${data.is_phishing ? '🚨 PHISHING DETECTED' : '✅ URL APPEARS SAFE'}</h2>
                <p>Phishing Probability: ${(data.phishing_probability * 100).toFixed(1)}%</p>
                <p>Risk Level: ${data.risk_level}</p>
            `;
            resultDiv.style.display = 'block';
        });
    </script>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        url = data.get('url', '')
        result = detector.predict(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    print("\n" + "="*60)
    print("PHISHING URL DETECTOR - Random Forest")
    print("="*60 + "\n")
    
    model_file = 'phishing_detector.pkl'
    
    if os.path.exists(model_file):
        print(f"Loading model from {model_file}...")
        try:
            detector.load_model(model_file)
        except:
            print("Training new model...")
            detector.train_from_datasets()
            detector.save_model(model_file)
    else:
        print("Training new model with real top sites...")
        detector.train_from_datasets(
            phishing_limit=500,
            legitimate_limit=1000,
            use_top_sites=True
        )
        detector.save_model(model_file)
    
    print("\n🌐 Starting Flask at: http://127.0.0.1:5000\n")
    app.run(debug=True, host='127.0.0.1', port=5000)
