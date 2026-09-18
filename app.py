from flask import Flask, jsonify, request
from flask_cors import CORS

from live_capture import capture_live_traffic

import pandas as pd
from pathlib import Path
import threading


# ============================================================
# Flask application setup
# ============================================================

app = Flask(__name__)
CORS(app)


# ============================================================
# Folder and file paths
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

REPORTS_FOLDER = BASE_DIR / "reports"
MODELS_FOLDER = BASE_DIR / "models"

FLOWS_FILE = REPORTS_FOLDER / "flows.csv"
THREATS_FILE = REPORTS_FOLDER / "threats.csv"

MODEL_FILE = MODELS_FOLDER / "threat_model.pkl"


# ============================================================
# Live capture lock
# ============================================================

capture_lock = threading.Lock()


# ============================================================
# Utility functions
# ============================================================

def read_csv_file(file_path):
    """
    Safely reads a CSV file.

    Returns an empty DataFrame if the file:
    - Does not exist
    - Is empty
    - Cannot be read
    """

    try:

        if not file_path.exists():
            return pd.DataFrame()

        if file_path.stat().st_size == 0:
            return pd.DataFrame()

        return pd.read_csv(file_path)

    except Exception as error:

        print(f"Error reading {file_path}: {error}")

        return pd.DataFrame()


def convert_records(dataframe):
    """
    Converts a DataFrame into JSON-compatible records.

    NaN values are converted into None.
    """

    if dataframe.empty:
        return []

    dataframe = dataframe.astype(object).where(
        pd.notnull(dataframe),
        None
    )

    return dataframe.to_dict(orient="records")


def calculate_summary(flows_df, threats_df):
    """
    Calculates the network risk summary.
    """

    total_flows = len(flows_df)
    total_threats = len(threats_df)

    high_threats = 0
    medium_threats = 0
    low_threats = 0

    average_risk_score = 0

    # --------------------------------------------------------
    # Threat severity calculation
    # --------------------------------------------------------

    if not threats_df.empty:

        if "severity" in threats_df.columns:

            severity_values = (
                threats_df["severity"]
                .astype(str)
                .str.lower()
                .str.strip()
            )

            high_threats = int(
                (severity_values == "high").sum()
            )

            medium_threats = int(
                (severity_values == "medium").sum()
            )

            low_threats = int(
                (severity_values == "low").sum()
            )

        # ----------------------------------------------------
        # Average risk score calculation
        # ----------------------------------------------------

        if "risk_score" in threats_df.columns:

            risk_scores = pd.to_numeric(
                threats_df["risk_score"],
                errors="coerce"
            ).dropna()

            if not risk_scores.empty:

                average_risk_score = round(
                    float(risk_scores.mean()),
                    2
                )

    # --------------------------------------------------------
    # Overall risk classification
    # --------------------------------------------------------

    if average_risk_score >= 70:

        overall_risk = "High"

    elif average_risk_score >= 40:

        overall_risk = "Medium"

    else:

        overall_risk = "Low"

    return {
        "total_flows": total_flows,
        "total_threats": total_threats,
        "high_threats": high_threats,
        "medium_threats": medium_threats,
        "low_threats": low_threats,
        "average_risk_score": average_risk_score,
        "overall_risk": overall_risk
    }


def get_ai_status():
    """
    Returns the AI model status.
    """

    return {
        "model_folder_exists": MODELS_FOLDER.exists(),
        "model_file_exists": MODEL_FILE.exists(),
        "model_path": str(MODEL_FILE)
    }


def get_capture_duration():
    """
    Reads and validates the capture duration.

    Default duration: 5 seconds
    Minimum duration: 1 second
    Maximum duration: 60 seconds
    """

    duration_value = request.args.get("duration", "5")

    try:

        duration = int(duration_value)

    except ValueError:

        raise ValueError(
            "Duration must be a valid integer."
        )

    if duration < 1 or duration > 60:

        raise ValueError(
            "Duration must be between 1 and 60 seconds."
        )

    return duration


# ============================================================
# Home API
# ============================================================

@app.route("/", methods=["GET"])
def home():
    """
    Checks whether the Flask API is running.
    """

    return jsonify({
        "message": "UniFlow Flask API is running",
        "status": "success"
    })


# ============================================================
# Health check API
# ============================================================

@app.route("/api/health", methods=["GET"])
def health_check():
    """
    Checks API health and reports file and AI model status.
    """

    return jsonify({
        "status": "healthy",
        "service": "UniFlow Flask API",
        "reports_folder": str(REPORTS_FOLDER),
        "flows_file_exists": FLOWS_FILE.exists(),
        "threats_file_exists": THREATS_FILE.exists(),
        "ai": get_ai_status()
    })


# ============================================================
# Summary API
# ============================================================

@app.route("/api/summary", methods=["GET"])
def get_summary():
    """
    Returns the network risk summary from CSV files.
    """

    flows_df = read_csv_file(FLOWS_FILE)
    threats_df = read_csv_file(THREATS_FILE)

    summary = calculate_summary(
        flows_df,
        threats_df
    )

    return jsonify(summary)


# ============================================================
# Threats API
# ============================================================

@app.route("/api/threats", methods=["GET"])
def get_threats():
    """
    Returns all detected threats.
    """

    threats_df = read_csv_file(THREATS_FILE)

    return jsonify({
        "status": "success",
        "count": len(threats_df),
        "threats": convert_records(threats_df)
    })


# ============================================================
# Flows API
# ============================================================

@app.route("/api/flows", methods=["GET"])
def get_flows():
    """
    Returns all detected network flows.
    """

    flows_df = read_csv_file(FLOWS_FILE)

    return jsonify({
        "status": "success",
        "count": len(flows_df),
        "flows": convert_records(flows_df)
    })


# ============================================================
# Complete dashboard API
# ============================================================

@app.route("/api/dashboard", methods=["GET"])
def get_dashboard_data():
    """
    Returns summary, threats, and flows together.
    """

    flows_df = read_csv_file(FLOWS_FILE)
    threats_df = read_csv_file(THREATS_FILE)

    summary = calculate_summary(
        flows_df,
        threats_df
    )

    return jsonify({
        "status": "success",
        "summary": summary,
        "threats": convert_records(threats_df),
        "flows": convert_records(flows_df)
    })


# ============================================================
# Live traffic analysis API
# ============================================================

@app.route("/api/live-analysis", methods=["GET"])
def live_analysis():
    """
    Captures and analyzes live network traffic.

    Default capture duration: 5 seconds.

    Optional example:
    /api/live-analysis?duration=10
    """

    # --------------------------------------------------------
    # Validate duration
    # --------------------------------------------------------

    try:

        duration = get_capture_duration()

    except ValueError as error:

        return jsonify({
            "status": "error",
            "message": str(error)
        }), 400

    # --------------------------------------------------------
    # Prevent simultaneous captures
    # --------------------------------------------------------

    if not capture_lock.acquire(blocking=False):

        return jsonify({
            "status": "busy",
            "message": (
                "Another live capture is already running. "
                "Please try again later."
            )
        }), 429

    try:

        print("\n" + "=" * 80)
        print("Starting live network capture...")
        print(f"Capture duration: {duration} seconds")
        print("=" * 80)

        result = capture_live_traffic(
            interface=None,
            duration=duration
        )

        print("Live network capture completed.")

        return jsonify(result)

    except PermissionError:

        return jsonify({
            "status": "error",
            "message": (
                "Permission denied. Run the terminal as Administrator "
                "or provide the required packet-capture permissions."
            )
        }), 403

    except FileNotFoundError as error:

        return jsonify({
            "status": "error",
            "message": (
                "Required file was not found. "
                f"Details: {str(error)}"
            )
        }), 500

    except Exception as error:

        print(f"Live analysis error: {error}")

        return jsonify({
            "status": "error",
            "message": str(error)
        }), 500

    finally:

        capture_lock.release()


# ============================================================
# API route list
# ============================================================

@app.route("/api/routes", methods=["GET"])
def get_routes():
    """
    Returns the available API endpoints.
    """

    return jsonify({
        "status": "success",
        "routes": {
            "home": "/",
            "health": "/api/health",
            "summary": "/api/summary",
            "threats": "/api/threats",
            "flows": "/api/flows",
            "dashboard": "/api/dashboard",
            "live_analysis": "/api/live-analysis",
            "live_analysis_custom": (
                "/api/live-analysis?duration=10"
            )
        }
    })


# ============================================================
# Run Flask application
# ============================================================

if __name__ == "__main__":

    REPORTS_FOLDER.mkdir(
        parents=True,
        exist_ok=True
    )

    MODELS_FOLDER.mkdir(
        parents=True,
        exist_ok=True
    )

    print("=" * 80)
    print("UniFlow Flask API")
    print("=" * 80)
    print(f"Base folder: {BASE_DIR}")
    print(f"Reports folder: {REPORTS_FOLDER}")
    print(f"Model file: {MODEL_FILE}")
    print(f"AI model available: {MODEL_FILE.exists()}")
    print("Server: http://127.0.0.1:5000")
    print("=" * 80)

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )