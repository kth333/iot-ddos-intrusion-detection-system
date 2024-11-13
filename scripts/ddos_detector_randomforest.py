from sklearn.ensemble import BaggingClassifier, RandomForestClassifier
from sklearn.metrics import accuracy_score, recall_score, precision_score, f1_score
from sklearn.model_selection import train_test_split
import pandas as pd
import numpy as np
import joblib

# Load dataset
df = pd.read_csv('/app/data/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv')

# Standardize column names by stripping whitespace
df.columns = df.columns.str.strip()

# Display label distribution and standardized column names
print("Label distribution:\n", df['Label'].value_counts())
print("Standardized column names:\n", df.columns.tolist())

# Replace infinite values and drop NULLs
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

# Map labels to binary values (standardize label name if necessary)
df['Label'] = df['Label'].map({'DDoS': 1, 'BENIGN': 0})

# Define and clean feature columns (remove leading/trailing spaces)
expected_features = ['Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max', 
    'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std', 'Bwd Packet Length Max', 
    'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow Bytes/s', 
    'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 
    'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 
    'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 
    'Bwd URG Flags', 'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s', 
    'Min Packet Length', 'Max Packet Length', 'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance', 
    'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 
    'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio', 'Average Packet Size', 
    'Avg Fwd Segment Size', 'Avg Bwd Segment Size', 'Fwd Header Length.1', 'Fwd Avg Bytes/Bulk', 
    'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 
    'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets', 
    'Subflow Bwd Bytes', 'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd', 
    'min_seg_size_forward', 'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean', 
    'Idle Std', 'Idle Max', 'Idle Min']

# Filter only columns that exist in the DataFrame to avoid KeyErrors
A = [col for col in expected_features if col in df.columns]

# Verify all required features are present
missing_features = set(expected_features) - set(A)
if missing_features:
    print("Warning: The following expected features are missing in the dataset:", missing_features)

# Split dataset
X_train, X_test, y_train, y_test = train_test_split(df[A], df['Label'], test_size=0.2, random_state=20)

# Initialize the model
R = RandomForestClassifier(n_estimators=100, max_depth=5, n_jobs=-1)  # Use all CPU cores
model = BaggingClassifier(estimator=R, n_estimators=100, max_samples=0.8, max_features=0.8)

# Train the model
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
joblib.dump((model, A), '/app/models/ddos_detector_model_with_features.joblib')
print("Model and feature list saved successfully.")