import os
import pandas as pd
import joblib

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline


# CSV file location
DATASET_FILE = "reports/flows.csv"

# Model folder and model file
MODEL_FOLDER = "models"
MODEL_FILE = os.path.join(
    MODEL_FOLDER,
    "threat_model.pkl"
)


def protocol_to_number(protocol):
    """
    Convert protocol name into its numerical value.
    """

    protocol = str(protocol).upper().strip()

    if protocol == "TCP":
        return 6

    if protocol == "UDP":
        return 17

    if protocol == "ICMP":
        return 1

    # If protocol is already a number
    try:
        return int(protocol)
    except ValueError:
        return 0


def train_model():
    """
    Train the AI anomaly-detection model.
    """

    # Check whether the dataset exists
    if not os.path.exists(DATASET_FILE):
        print("Dataset file not found:")
        print(DATASET_FILE)
        return

    # Read CSV file
    data = pd.read_csv(DATASET_FILE)

    print("Dataset loaded successfully.")
    print("Dataset columns:", list(data.columns))
    print("Total records:", len(data))

    # Required columns
    required_columns = [
        "src_port",
        "dst_port",
        "protocol",
        "packet_count",
        "total_bytes"
    ]

    # Check for missing columns
    missing_columns = [
        column
        for column in required_columns
        if column not in data.columns
    ]

    if missing_columns:
        print("Missing columns:", missing_columns)
        print("Please check your reports/flows.csv file.")
        return

    # Convert protocol into a numerical value
    data["protocol_number"] = data["protocol"].apply(
        protocol_to_number
    )

    # Convert values into numeric format
    numeric_columns = [
        "src_port",
        "dst_port",
        "packet_count",
        "total_bytes"
    ]

    for column in numeric_columns:
        data[column] = pd.to_numeric(
            data[column],
            errors="coerce"
        )

    # Replace invalid or empty values with zero
    data[numeric_columns] = data[numeric_columns].fillna(0)

    # Avoid division by zero
    data["packet_count"] = data["packet_count"].replace(
        0,
        1
    )

    # Calculate average bytes per packet
    data["bytes_per_packet"] = (
        data["total_bytes"] /
        data["packet_count"]
    )

    # Select features for AI model
    features = data[
        [
            "src_port",
            "dst_port",
            "protocol_number",
            "packet_count",
            "total_bytes",
            "bytes_per_packet"
        ]
    ].fillna(0)

    # Create the AI model
    model = Pipeline(
        steps=[
            (
                "scaler",
                StandardScaler()
            ),
            (
                "detector",
                IsolationForest(
                    n_estimators=150,
                    contamination="auto",
                    random_state=42
                )
            )
        ]
    )

    # Train the model
    print("Training AI model...")
    model.fit(features)

    # Automatically create the models folder
    os.makedirs(
        MODEL_FOLDER,
        exist_ok=True
    )

    # Save the trained model
    joblib.dump(
        model,
        MODEL_FILE
    )

    print()
    print("AI model trained successfully.")
    print("Training records:", len(features))
    print("Model saved at:", MODEL_FILE)


if __name__ == "__main__":
    train_model()