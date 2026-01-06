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
    * Next time the script is ran, it will load the saved model (although retraining can be done by deleting that file with `rm phishing_detector.pkl`

### Uses and Limitations
This project is NOT production ready; rather, it is a good way to familirize with ML and Cybersecurity. It is not perfect since it is only using a limited number of open-source data sets. Additionally, there are quite a few false positives/negatives with the trained ML model. It also does not check against live blacklists (something that can be expanded upon later). 

## How to Run on macOS
1. Install Python (if not alreadt installed)
   Check if Python 3 is installed
   ```
   python3 --version
   ```
   If not installed, install via Homebrew
   ```
   brew install python3
   ```
2. Create a Project Directory
   Create and navigate to project folder
   ```
   mkdir ~/phishing-detector
   cd ~/phishing-detector
   ```
   Save the code as phishing_detector.py
3. Create a Virtual Environment (recommended due to all of the dependencies we will be downloading in step 4)
   ("venv_name" is a place holder. Please feel free to create any virtual environment name)
   ```
   python3 -m venv venv_name
   ```
   Activate the enviroment with the following command
   ```
   source venv_name/bin/activate
   ```
   You should now see (venv_name) in your terminal prompt
4. Install Dependencies
   ```
   pip install flask scikit-learn pandas numpy requests
   ```
5. Run the Application
   Bash
   ```
   python3 phishing_detector.py
   ```
6. Your terminal will display various information, such as training new model with ULRs from OpenPhish, PhishTank, and Tranco. Model will be saved to `phishing_detector.pkl` and start Flask at `http://127.0.0.1:5000`
   Navigate to your preferred browser and type in `http://127.0.0.1:5000` to launch the web-based UI.
7. Stop Server and Deactivate Environment
   Navigate to your terminal and enter `control + C` to stop the appliction from running. Then enter `deactivate` into your terminal to close the virtual environment.

### Privacy
The model is only accessible from your computer (refer to the line `app.run(debug=True, host='127.0.0.1', port=5000)`. 
You could change that section to `host='0.0.0.0', port=5000` if you wanted all local machines on your network to access it. This is still not accessible from the internet since it will be blocked by your router. 




   
