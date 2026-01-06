# Phishing_Detector.py
Machine learning-based phishing URL detector with a web interface via Flask. Running this script in macOS; however, can easily be altered to work on Linux/Windows. 

## Core Functionality
 1. Downloads Real Data
    * Phishing URLs are from OpenPhish and PhishTank (verified malicious sites).
    * Legitimate URLs are from Tranco (top 1000 most popular sites like Google, Amazon, etc).
 2. Trains a Machine Learning Model
    * Uses a Random Forest algorithm to generate an ensemble of 150 decision trees.
    * Extracts 15+ features from URLs, to include length, special characters, suspicious keywords, top-level-domains, etc.
    * Learns patterns that distinguish phishing from legitimate sites.
 3. Provides a Web Interface
    * Flask web server with a simple UI.
    * Users can input any URL and the UI will display probability scores and risk levels.
 4. Saves the Model
    * The machine learning training is saved to phishing_detector.pkl
    * Next time the script is ran, it will load the saved model (although retraining can be done by deleting that file with \rm phishing_detector.pkl

## Uses and Limitations
This project is NOT production ready; rather, it is a good way to familirize with ML and Cybersecurity. It is not perfect since it is only using a limited number of open-source data sets. Additionally, there are quite a few false positives/negatives with the trained ML model. It also does not check against live blacklists (something that can be expanded upon later). 

## How to Run on macOS
1. 
