import pandas as pd
import numpy as np

def preprocess_features(features, ohe, scaler):
    df = pd.DataFrame([features])
    categorical_cols = ['proto']
    numerical_cols = ['length']

    # Ensure all expected columns are present
    for col in categorical_cols + numerical_cols:
        if col not in df.columns:
            df[col] = 0

    # Encode categorical variables
    X_encoded = ohe.transform(df[categorical_cols])

    # Scale numerical features
    X_scaled = scaler.transform(df[numerical_cols])

    # Combine features
    X_preprocessed = np.hstack([X_scaled, X_encoded.toarray()])

    return X_preprocessed