import pandas as pd
import numpy as np
from sklearn.ensemble import BaggingClassifier, RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, recall_score, precision_score, f1_score
import joblib

# Load dataset
df = pd.read_csv('/app/data/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv')

# Standardize column names by stripping whitespace
df.columns = df.columns.str.strip()

# Replace infinite values and drop NULLs
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

# Map labels to binary values (standardize label name if necessary)
df['Label'] = df['Label'].map({'DDoS': 1, 'BENIGN': 0})

# Define and clean feature columns
selected_features = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Flow Bytes/s', 'Flow Packets/s',
    'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
    'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std',
    'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count'
]

# Filter only columns that exist in the DataFrame to avoid KeyErrors
selected_features = [col for col in selected_features if col in df.columns]

# Check for missing features
missing_features = set(selected_features) - set(df.columns)
if missing_features:
    print("Warning: The following expected features are missing in the dataset:", missing_features)

# Split dataset
X = df[selected_features]
y = df['Label']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=20)

# Initialize and train the model
base_model = RandomForestClassifier(n_estimators=100, max_depth=5, n_jobs=-1)
model = BaggingClassifier(estimator=base_model, n_estimators=100, max_samples=0.8, max_features=0.8)
model.fit(X_train, y_train)

# Evaluate the model
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
recall = recall_score(y_test, y_pred)
precision = precision_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)

print("Accuracy:", accuracy)
print("Recall:", recall)
print("Precision:", precision)
print("F1 Score:", f1)

# Save the model and feature list to ensure consistency during inference
joblib.dump((model, selected_features), '/app/models/ddos_detector_model_with_features.joblib')
print("Model and feature list saved successfully.")