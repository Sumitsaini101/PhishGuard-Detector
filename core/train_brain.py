import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import joblib
import os
from feature_extractor import extract_features

# 1. Configuration - Bulletproof Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(BASE_DIR, "..", "dataset", "phishing_data.csv")
MODEL_PATH = os.path.join(BASE_DIR, "phishing_model.pkl")

print("[*] Initializing Advanced AI Training Protocol...")

# 2. Load the Dataset
try:
    df = pd.read_csv(DATASET_PATH)
    print(f"[+] Loaded dataset successfully: {len(df)} rows.")
    print(f"[*] Original columns found: {df.columns.tolist()}")
except FileNotFoundError:
    print(f"[-] ERROR: Could not find {DATASET_PATH}")
    exit()

# 3. Smart Column Detection (Enterprise Fix for KeyError)
# Convert columns to lowercase and strip spaces for easier matching
df.columns = df.columns.str.strip().str.lower()

# Find the URL column
url_col = next((col for col in df.columns if col in ['url', 'urls', 'domain', 'website']), None)
# Find the Label column
label_col = next((col for col in df.columns if col in ['label', 'class', 'status', 'result', 'phishing']), None)

if not url_col or not label_col:
    print("[-] ERROR: Could not automatically detect the URL or Label columns.")
    print(f"[*] Available columns (lowercased): {df.columns.tolist()}")
    print("Please ensure your CSV has a column for the link and a column for the result.")
    exit()

print(f"[+] Auto-detected URL column: '{url_col}'")
print(f"[+] Auto-detected Label column: '{label_col}'")

# 4. Extract Features
print("[*] Extracting 9-dimensional features... (This may take a moment)")
X_raw = df[url_col].apply(extract_features)
X = np.array(X_raw.tolist())
y = df[label_col].values

# 5. Split data (80% for training, 20% for testing)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 6. Train the Random Forest Model
print("[*] Training Random Forest Classifier (100 Trees)...")
model = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
model.fit(X_train, y_train)

# 7. Evaluate the Model
predictions = model.predict(X_test)
accuracy = accuracy_score(y_test, predictions)
print("\n" + "="*40)
print(f"🚀 MODEL ACCURACY: {accuracy * 100:.2f}%")
print("="*40)
print("\nDetailed Classification Report:")
print(classification_report(y_test, predictions))

# 8. Save the Model
joblib.dump(model, MODEL_PATH)
print(f"\n[+] New high-accuracy model saved as {MODEL_PATH}")
print("[+] Your PhishGuard Dashboard is ready to use!")