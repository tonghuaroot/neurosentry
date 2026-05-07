#!/usr/bin/env python3
"""
NeuroSentry Capture The Model — Scoring Server

Tracks participant attempts and verifies successful exfiltration during the
hands-on lab challenge.
"""

import hashlib
import json
import logging
import os
import sqlite3
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, List, Any

from flask import Flask, request, jsonify, send_from_directory
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST

# Configuration
CHALLENGE_DURATION = int(os.getenv("CHALLENGE_DURATION", "900"))  # 15 minutes
MODEL_PATH = os.getenv("MODEL_PATH", "/models/llama-2-7b.safetensors")
STOLEN_PATH = "/tmp/stolen"
SCORING_DB = "/data/scoring.db"
LOG_FILE = "/data/attempts.log"

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("scoring-server")

# Prometheus metrics
attempt_counter = Counter(
    'ctf_attempts_total',
    'Total number of exfiltration attempts',
    ['method', 'result']
)
attempt_duration = Histogram(
    'ctf_attempt_duration_seconds',
    'Time spent on attempts'
)
active_participants = Gauge(
    'ctf_active_participants',
    'Number of active participants'
)
successful_exfiltrations = Gauge(
    'ctf_successful_exfiltrations',
    'Number of successful model exfiltrations'
)

# Flask app
app = Flask(__name__)

# Database setup
def init_db():
    """Initialize the scoring database."""
    conn = sqlite3.connect(SCORING_DB)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            participant_id TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            method TEXT NOT NULL,
            success BOOLEAN DEFAULT FALSE,
            details TEXT,
            duration_seconds REAL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS participants (
            id TEXT PRIMARY KEY,
            start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
            end_time DATETIME,
            attempts_count INTEGER DEFAULT 0,
            successful BOOLEAN DEFAULT FALSE
        )
    ''')
    conn.commit()
    conn.close()


def log_attempt(participant_id: str, method: str, success: bool,
                details: Optional[str] = None, duration: Optional[float] = None) -> int:
    """Log an attempt to the database."""
    conn = sqlite3.connect(SCORING_DB)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO attempts (participant_id, method, success, details, duration_seconds)
        VALUES (?, ?, ?, ?, ?)
    ''', (participant_id, method, success, details, duration))
    attempt_id = cursor.lastrowid

    # Update participant stats
    cursor.execute('''
        INSERT OR IGNORE INTO participants (id) VALUES (?)
    ''', (participant_id,))
    cursor.execute('''
        UPDATE participants SET
            attempts_count = attempts_count + 1,
            successful = successful OR ?
        WHERE id = ?
    ''', (success, participant_id))
    conn.commit()
    conn.close()

    # Update metrics
    attempt_counter.labels(method=method, result='success' if success else 'failed').inc()
    if success:
        successful_exfiltrations.inc()

    logger.info(f"Attempt {attempt_id}: {participant_id} - {method} - {'SUCCESS' if success else 'FAILED'}")
    return attempt_id


def get_model_hash() -> Optional[str]:
    """Calculate MD5 hash of the protected model file."""
    if not os.path.exists(MODEL_PATH):
        logger.warning(f"Model file not found: {MODEL_PATH}")
        return None

    md5 = hashlib.md5()
    try:
        with open(MODEL_PATH, 'rb') as f:
            # Read in chunks to handle large files
            for chunk in iter(lambda: f.read(8192), b''):
                md5.update(chunk)
        return md5.hexdigest()
    except Exception as e:
        logger.error(f"Error calculating model hash: {e}")
        return None


def verify_exfiltration(file_path: str) -> Dict[str, Any]:
    """Verify if the exfiltrated file matches the original model."""
    result = {
        "exists": False,
        "readable": False,
        "size_match": False,
        "hash_match": False,
        "original_hash": None,
        "file_hash": None,
        "file_size": 0,
        "original_size": 0
    }

    # Check original model
    if not os.path.exists(MODEL_PATH):
        result["error"] = "Original model not found"
        return result

    result["original_size"] = os.path.getsize(MODEL_PATH)
    result["original_hash"] = get_model_hash()

    # Check exfiltrated file
    if not os.path.exists(file_path):
        result["error"] = "Exfiltrated file not found"
        return result

    result["exists"] = True
    result["file_size"] = os.path.getsize(file_path)
    result["size_match"] = result["file_size"] == result["original_size"]

    # Check readability
    try:
        with open(file_path, 'rb') as f:
            f.read(1)
        result["readable"] = True
    except Exception as e:
        result["error"] = f"Cannot read file: {e}"
        return result

    # Calculate hash
    md5 = hashlib.md5()
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                md5.update(chunk)
        result["file_hash"] = md5.hexdigest()
        result["hash_match"] = result["file_hash"] == result["original_hash"]
    except Exception as e:
        result["error"] = f"Error calculating hash: {e}"

    return result


# API Routes

@app.route('/')
def index():
    """Scoring server homepage."""
    return jsonify({
        "challenge": "Capture The Model",
        "format": "hands-on lab",
        "status": "running",
        "endpoints": {
            "/status": "Get current challenge status",
            "/verify": "POST with file path to verify exfiltration",
            "/attempts": "Get all attempts",
            "/submit": "POST with method and details to log attempt",
            "/metrics": "Prometheus metrics",
            "/model/hash": "Get model hash (for verification)"
        }
    })


@app.route('/status')
def status():
    """Get current challenge status."""
    model_hash = get_model_hash()
    model_size = os.path.getsize(MODEL_PATH) if os.path.exists(MODEL_PATH) else 0

    conn = sqlite3.connect(SCORING_DB)
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM participants')
    total_participants = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM participants WHERE successful = 1')
    successful_count = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM attempts')
    total_attempts = cursor.fetchone()[0]
    conn.close()

    active_participants.set(total_participants)

    return jsonify({
        "challenge": "Capture The Model",
        "status": "active",
        "model": {
            "path": MODEL_PATH,
            "size_bytes": model_size,
            "size_gb": round(model_size / (1024**3), 2),
            "hash": model_hash,
            "exists": os.path.exists(MODEL_PATH)
        },
        "statistics": {
            "total_participants": total_participants,
            "successful_exfiltrations": successful_count,
            "total_attempts": total_attempts,
            "success_rate": round(successful_count / total_participants * 100, 2) if total_participants > 0 else 0
        },
        "duration_limit_seconds": CHALLENGE_DURATION
    })


@app.route('/verify', methods=['POST'])
def verify():
    """Verify if a file is a valid exfiltration."""
    data = request.get_json()
    if not data or 'file_path' not in data:
        return jsonify({"error": "Missing file_path"}), 400

    file_path = data['file_path']
    participant_id = data.get('participant_id', 'anonymous')

    result = verify_exfiltration(file_path)

    # Log the attempt
    is_success = result.get("hash_match", False) and result.get("readable", False)
    log_attempt(
        participant_id,
        "file_verification",
        is_success,
        json.dumps(result),
        data.get("duration")
    )

    return jsonify(result)


@app.route('/submit', methods=['POST'])
def submit_attempt():
    """Submit an attempt for logging."""
    data = request.get_json()
    if not data or 'method' not in data:
        return jsonify({"error": "Missing method"}), 400

    participant_id = data.get('participant_id', 'anonymous')
    method = data['method']
    success = data.get('success', False)
    details = data.get('details')
    duration = data.get('duration')

    attempt_id = log_attempt(participant_id, method, success, details, duration)

    return jsonify({
        "attempt_id": attempt_id,
        "message": "Attempt logged"
    })


@app.route('/attempts')
def list_attempts():
    """Get all attempts."""
    limit = request.args.get('limit', 100, type=int)
    participant_id = request.args.get('participant_id')

    conn = sqlite3.connect(SCORING_DB)
    cursor = conn.cursor()

    if participant_id:
        cursor.execute('''
            SELECT id, participant_id, timestamp, method, success, details, duration_seconds
            FROM attempts WHERE participant_id = ?
            ORDER BY timestamp DESC LIMIT ?
        ''', (participant_id, limit))
    else:
        cursor.execute('''
            SELECT id, participant_id, timestamp, method, success, details, duration_seconds
            FROM attempts ORDER BY timestamp DESC LIMIT ?
        ''', (limit,))

    attempts = []
    for row in cursor.fetchall():
        attempts.append({
            "id": row[0],
            "participant_id": row[1],
            "timestamp": row[2],
            "method": row[3],
            "success": bool(row[4]),
            "details": row[5],
            "duration_seconds": row[6]
        })

    conn.close()
    return jsonify(attempts)


@app.route('/model/hash')
def model_hash():
    """Get the model hash for verification."""
    model_hash = get_model_hash()
    if model_hash is None:
        return jsonify({"error": "Model not found"}), 404

    return jsonify({
        "hash": model_hash,
        "path": MODEL_PATH,
        "size": os.path.getsize(MODEL_PATH)
    })


@app.route('/leaderboard')
def leaderboard():
    """Get the leaderboard."""
    conn = sqlite3.connect(SCORING_DB)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT participant_id, start_time, attempts_count, successful,
               (SELECT MAX(timestamp) FROM attempts WHERE participant_id = p.id) as last_attempt
        FROM participants p
        ORDER BY successful DESC, attempts_count ASC, start_time ASC
        LIMIT 20
    ''')

    leaders = []
    for row in cursor.fetchall():
        leaders.append({
            "participant_id": row[0],
            "start_time": row[1],
            "attempts": row[2],
            "successful": bool(row[3]),
            "last_attempt": row[4]
        })

    conn.close()
    return jsonify(leaders)


@app.route('/metrics')
def metrics():
    """Prometheus metrics endpoint."""
    return generate_latest(), 200, {'Content-Type': CONTENT_TYPE_LATEST}


@app.route('/health')
def health():
    """Health check endpoint."""
    return jsonify({"status": "healthy"}), 200


def main():
    """Main entry point."""
    # Ensure data directory exists
    os.makedirs(os.path.dirname(SCORING_DB), exist_ok=True)
    os.makedirs(STOLEN_PATH, exist_ok=True)

    # Initialize database
    init_db()

    logger.info("Starting NeuroSentry CTF Scoring Server")
    logger.info(f"Model path: {MODEL_PATH}")
    logger.info(f"Challenge duration: {CHALLENGE_DURATION}s")

    app.run(host='0.0.0.0', port=8080, debug=False)


if __name__ == '__main__':
    main()
