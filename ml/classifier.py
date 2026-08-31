#!/usr/bin/env python3
"""
classifier.py — Offline ML training pipeline for Honeypot Orchestrator.

Reads accumulated events out of database/honeypot.db, engineers features,
trains a RandomForestClassifier, reports accuracy and feature importance,
and saves the trained model with joblib.

Usage:
    python3 classifier.py
    python3 classifier.py --db ../database/honeypot.db
"""
import argparse
import sqlite3
import os
import sys
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, accuracy_score
import joblib


def load_events(db_path):
    if not os.path.exists(db_path):
        sys.exit(f"[!] Database not found at {db_path}. Run the simulator first to generate data.")
    conn = sqlite3.connect(db_path)
    df = pd.read_sql_query("SELECT * FROM events", conn)
    conn.close()
    return df


def engineer_features(df):
    """Builds the feature table for ML model."""
    df = df.copy()
    df["payload"] = df["payload"].fillna("")
    df["payload_length"] = df["payload"].str.len()

    # per-source aggregate features
    df = df.sort_values("id")
    df["request_count"] = df.groupby("source_ip").cumcount() + 1
    df["failed_attempts"] = (
        df[df["event_type"] == "LOGIN_ATTEMPT"]
        .assign(is_failed=lambda x: (x["status"] == "failed").astype(int))
        .groupby("source_ip")["is_failed"].cumsum()
    )
    df["failed_attempts"] = df["failed_attempts"].fillna(0)

    df["is_ssh"] = (df["protocol"] == "SSH").astype(int)
    df["is_http"] = (df["protocol"] == "HTTP").astype(int)
    df["is_db"] = (df["protocol"] == "DB").astype(int)
    df["has_login"] = (df["event_type"] == "LOGIN_ATTEMPT").astype(int)
    df["has_sqli_pattern"] = df["payload"].str.contains(
        r"union\s+select|or\s+'?1'?=?'?1|drop\s+table", case=False, regex=True
    ).astype(int)
    df["has_xss_pattern"] = df["payload"].str.contains(
        r"<script|onerror=|javascript:", case=False, regex=True
    ).astype(int)
    df["has_cmd_pattern"] = df["payload"].str.contains(
        r";\s*(?:cat|ls|whoami|wget|curl)|`.*`", case=False, regex=True
    ).astype(int)

    feature_cols = [
        "request_count", "failed_attempts", "payload_length",
        "is_ssh", "is_http", "is_db", "has_login",
        "has_sqli_pattern", "has_xss_pattern", "has_cmd_pattern",
    ]
    return df, feature_cols


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default=os.path.join(os.path.dirname(__file__), "..", "database", "honeypot.db"))
    parser.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "models", "attack_classifier.joblib"))
    args = parser.parse_args()

    print("[+] Loading events from", args.db)
    df = load_events(args.db)
    df = df[df["attack_type"].notna()]
    if len(df) < 20:
        sys.exit(f"[!] Only {len(df)} labeled events found. Run the simulator (e.g. --attackers 15) to generate more data first.")

    print(f"[+] Loaded {len(df)} events, {df['attack_type'].nunique()} attack classes")

    df, feature_cols = engineer_features(df)
    X = df[feature_cols].fillna(0)
    y = df["attack_type"]

    le = LabelEncoder()
    y_enc = le.fit_transform(y)

    # Stratified split needs >=2 samples per class
    class_counts = pd.Series(y_enc).value_counts()
    can_stratify = y.nunique() > 1 and class_counts.min() >= 2
    if not can_stratify:
        print("[!] Some attack classes have <2 samples — using a non-stratified split. "
              "Run the simulator with more --attackers for a more balanced dataset.")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y_enc, test_size=0.25, random_state=42, stratify=y_enc if can_stratify else None
    )

    print("[+] Training RandomForestClassifier...")
    clf = RandomForestClassifier(n_estimators=200, max_depth=8, random_state=42, class_weight="balanced")
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"\n[+] Test accuracy: {acc:.2%}\n")
    print(classification_report(y_test, y_pred, target_names=le.classes_, zero_division=0))

    importances = sorted(zip(feature_cols, clf.feature_importances_), key=lambda x: -x[1])
    print("[+] Feature importance:")
    for name, imp in importances:
        bar = "█" * int(imp * 40)
        print(f"    {name:20s} {imp:.3f} {bar}")

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    joblib.dump({"model": clf, "label_encoder": le, "feature_cols": feature_cols}, args.out)
    print(f"\n[+] Model saved to {args.out}")


if __name__ == "__main__":
    main()
