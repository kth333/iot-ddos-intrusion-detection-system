import pandas as pd

# Read in the dataset for Training Set Normal Traffic
Training_Normal_Traffic = pd.read_csv('/app/data/Training_Set_Normal_Traffic.csv')

# Find out the length of the dataset for Training Set Normal Traffic
print(len(Training_Normal_Traffic))

# Display the first few rows
Training_Normal_Traffic

# Read in the dataset for Training Set Attack Traffic
Training_Attack_Traffic = pd.read_csv('/app/data/Training_Set_Attack_Traffic.csv')

# The same length will be used for Training Attack Traffic dataset so that we do not have an imbalanced dataset that could result in classification bias

# Randomly select 118 rows
#Training_Attack_Traffic_subset = Training_Attack_Traffic.sample(n=len(Training_Normal_Traffic), random_state=42)  # random_state ensures reproducibility

# Now Training_Attack_Traffic_subset contains 118 randomly selected rows
#print(len(Training_Attack_Traffic_subset))
# Display the first few rows
Training_Attack_Traffic

# Concatenate the two DataFrames vertically
Training_Data = pd.concat([Training_Normal_Traffic, Training_Attack_Traffic], ignore_index=True)

# Now verify combined_data contains both Training_Normal_Traffic and Training_Attack_Traffic_subset rows
Training_Data

# Read in the dataset for Testing Set Normal Traffic
Testing_Normal_Traffic = pd.read_csv('/app/data/Test_Set_Normal_Traffic.csv')


# Find out the length of the dataset for Testing Set Normal Traffic
print(len(Testing_Normal_Traffic))

# Display the first few rows
Testing_Normal_Traffic.head()

# Read in the dataset for Testing Set Attack Traffic
Testing_Attack_Traffic = pd.read_csv('/app/data/Test_Set_Attack_Traffic.csv')

# The same length will be used for Training Attack Traffic dataset so that we do not have an imbalanced dataset that could result in classification bias

# Randomly select 118 rows
#Testing_Attack_Traffic_subset = Testing_Attack_Traffic.sample(n=len(Testing_Normal_Traffic), random_state=42)  # random_state ensures reproducibility

# Now Training_Attack_Traffic_subset contains 118 randomly selected rows
#print(len(Testing_Attack_Traffic_subset))

# Display the first few rows
Testing_Attack_Traffic

# Concatenate the two DataFrames vertically
Testing_Data = pd.concat([Testing_Normal_Traffic, Testing_Attack_Traffic], ignore_index=True)

# Now verify combined_data contains both Testing_Normal_Traffic and Testing_Attack_Traffic_subset rows
Testing_Data

"""Final Training Dataset"""

print(Training_Data.shape)

Training_Data

"""Final Testing Dataset"""

print(Testing_Data.shape)

Testing_Data

print(Training_Data.columns)

import pandas as pd
import numpy as np
import tensorflow as tf
import joblib
from tensorflow import keras
from tensorflow.keras import layers
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.model_selection import train_test_split

# Separate features and labels
X = Training_Data.drop(['attack', 'category', 'subcategory'], axis=1)
y = Training_Data['attack']

# Drop high-cardinality columns
X = X.drop(['saddr', 'sport', 'daddr', 'dport'], axis=1)

# Identify categorical and numerical columns AFTER dropping
categorical_cols = ['proto', 'state_number']  # Only include existing columns
numerical_cols = ['stddev', 'N_IN_Conn_P_SrcIP', 'min', 'mean',
                  'N_IN_Conn_P_DstIP', 'drate', 'srate', 'max', 'seq']

# Initialize OneHotEncoder
from sklearn.preprocessing import OneHotEncoder
ohe = OneHotEncoder(sparse_output=False, handle_unknown='ignore')

# Fit on training data
X_encoded = ohe.fit_transform(X[categorical_cols])

# Save the OneHotEncoder after fitting
joblib.dump(ohe, '/app/models/ohe.joblib')

# Scale numerical features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X[numerical_cols])

# Save the scaler after fitting
joblib.dump(scaler, '/app/models/scaler.joblib')

# Combine numerical and categorical features
X_preprocessed = np.hstack([X_scaled, X_encoded])

# Similarly preprocess the test data
X_test = Testing_Data.drop(['attack', 'category', 'subcategory'], axis=1)
y_test = Testing_Data['attack']

# Drop high-cardinality columns in testing data
X_test = X_test.drop(['saddr', 'sport', 'daddr', 'dport'], axis=1)

# Transform categorical variables using the same encoder
X_test_encoded = ohe.transform(X_test[categorical_cols])

# Scale numerical features using the same scaler
X_test_scaled = scaler.transform(X_test[numerical_cols])

# Combine numerical and categorical features
X_test_preprocessed = np.hstack([X_test_scaled, X_test_encoded])

# Split the training data into training and validation sets
X_train, X_val, y_train, y_val = train_test_split(
    X_preprocessed, y, test_size=0.2, stratify=y, random_state=42)

# Build the neural network model
input_shape = X_train.shape[1]

model = keras.Sequential([
    layers.Dense(64, activation='relu', input_shape=(input_shape,)),
    layers.Dense(32, activation='relu'),
    layers.Dense(1, activation='sigmoid')  # Binary classification
])

# Compile the model
model.compile(optimizer='adam',
              loss='binary_crossentropy',
              metrics=['accuracy'])

# Train the model
history = model.fit(X_train, y_train,
                    epochs=20,
                    batch_size=32,
                    validation_data=(X_val, y_val))

# Evaluate the model on test data
test_loss, test_accuracy = model.evaluate(X_test_preprocessed, y_test)
print(f'Test Accuracy: {test_accuracy}')

# Make predictions
y_pred = model.predict(X_test_preprocessed)
y_pred_classes = (y_pred > 0.5).astype("int32")

# Classification report
from sklearn.metrics import classification_report

print(classification_report(y_test, y_pred_classes))

# Save the model
model.save('/app/models/ddos_detection_model.keras')