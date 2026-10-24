import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib
import os


class HybridIDSEngine:
    def __init__(self, model_path="models/ids_model.pkl", dataset_path=None):
        self.model_path = model_path
        self.model = None

        if os.path.exists(self.model_path):
            self.model = joblib.load(self.model_path)
        elif dataset_path and os.path.exists(dataset_path):
            self.train_model(dataset_path)
        else:
            print("[*] No dataset or saved model found. Initializing with default baseline weights...")
            self._train_fallback_model()

    def train_model(self, csv_path):
        print(f"[*] Training Random Forest model using dataset: {csv_path}...")
        df = pd.read_csv(csv_path)

        # Clean column names
        df.columns = df.columns.str.strip().str.lower().str.replace(' ', '_').str.replace('/', '_')

        # Map common CICIDS2017 column variations safely
        col_mapping = {
            'flow_duration': ['flow_duration', 'duration'],
            'packet_rate': ['flow_packets_s', 'packet_rate', 'total_fwd_packets'],
            'syn_flag_count': ['syn_flag_count', 'fwd_psh_flags', 'fin_flag_count'],
            'unique_dst_ports': ['destination_port', 'dst_port', 'unique_dst_ports']
        }

        X = pd.DataFrame()
        for target_col, possible_names in col_mapping.items():
            found = False
            for name in possible_names:
                if name in df.columns:
                    X[target_col] = pd.to_numeric(df[name], errors='coerce').fillna(0)
                    found = True
                    break
            if not found:
                X[target_col] = 0.0

        # --- FIX: Clean out infinities and missing values ---
        X = X.replace([np.inf, -np.inf], np.nan).fillna(0)

        label_col = None
        for col in df.columns:
            if 'label' in col or 'class' in col:
                label_col = col
                break

        if label_col:
            y = df[label_col].fillna('Benign')
        else:
            y = ['Benign'] * len(df)

        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.model.fit(X, y)

        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        joblib.dump(self.model, self.model_path)
        print(f"[+] Model successfully trained and saved to {self.model_path}")

    def _train_fallback_model(self):
        X_train = np.array([
            [1000, 10, 1, 1],
            [500, 1500, 800, 2],
            [2000, 5, 2, 50],
        ])
        y_train = ['Benign', 'DoS / SYN Flood', 'Port Scan / Reconnaissance']
        self.model = RandomForestClassifier(n_estimators=10, random_state=42)
        self.model.fit(X_train, y_train)

    def analyze_traffic(self, flow_features):
        duration = flow_features.get('flow_duration', 0)
        pkt_rate = flow_features.get('packet_rate', 0)
        syn_count = flow_features.get('syn_flag_count', 0)
        dst_ports = flow_features.get('unique_dst_ports', 1)

        if dst_ports > 25:
            return {
                "prediction": "Port Scan / Reconnaissance",
                "severity": "MEDIUM",
                "confidence": 0.98,
                "explanation": f"Rule triggered: High port fan-out detected ({dst_ports} distinct ports accessed)."
            }

        if pkt_rate > 1000 and syn_count > 400:
            return {
                "prediction": "DoS / SYN Flood",
                "severity": "HIGH",
                "confidence": 0.99,
                "explanation": f"Rule triggered: Excessive packet rate ({pkt_rate} pkts/sec) with high SYN flag volume."
            }

        if self.model:
            X_input = np.array([[duration, pkt_rate, syn_count, dst_ports]])
            prediction = self.model.predict(X_input)[0]
            probabilities = self.model.predict_proba(X_input)[0]
            confidence = float(np.max(probabilities))

            if prediction != "Benign":
                return {
                    "prediction": prediction,
                    "severity": "HIGH" if confidence > 0.8 else "MEDIUM",
                    "confidence": round(confidence, 4),
                    "explanation": "ML model flagged anomaly based on historical feature distribution."
                }

        return {
            "prediction": "Benign",
            "severity": "LOW",
            "confidence": 0.95,
            "explanation": "Traffic profile matches normal operational baseline."
        }