import joblib

# 1. Unfreeze the model (Handles being run from the root or the core folder)
print("Loading the frozen brain...\n")
try:
    model = joblib.load("core/phishing_model.pkl")
except FileNotFoundError:
    model = joblib.load("phishing_model.pkl")

# 2. Ask the model for its configuration
print("--- MODEL SETTINGS ---")
print(f"Algorithm used: {model.__class__.__name__}")
print(f"Number of Decision Trees: {model.n_estimators}\n")

# 3. Ask the model what it learned (Feature Importances)
print("--- WHAT THE MODEL THINKS IS IMPORTANT ---")
importances = model.feature_importances_

# UPDATED: The exact 9 features in the exact order outputted by our feature_extractor.py
features = [
    "Total URL Length", 
    "Domain Length", 
    "Total Dots", 
    "Hyphens in Domain", 
    "Presence of '@' Symbol", 
    "Raw IP Address Detection", 
    "Suspicious Keyword Count", 
    "HTTPS Status", 
    "Subdomain Count"
]

# Combine the features with their scores and sort them from highest to lowest impact
feature_impacts = sorted(zip(features, importances), key=lambda x: x[1], reverse=True)

# Loop through the sorted list and print the results
for rank, (feature_name, importance_score) in enumerate(feature_impacts, 1):
    # Convert the math score into a clean percentage
    percentage = round(importance_score * 100, 2)
    print(f"{rank}. {feature_name}: {percentage}% impact on final decision")