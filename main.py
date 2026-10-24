from src.feature_extract import extract_features
from src.detection_engine import HybridIDSEngine
import pandas as pd

def run_mandatory_scenarios():
    print("=== INITIALIZING AI-DRIVEN IDS TEST RUNNER ===\n")
    engine = HybridIDSEngine()

    # Define test samples representing the 5 mandatory scenarios
    scenarios = {
        "Scenario 1: Normal Baseline": {
            'flow_duration': 5000, 'packet_rate': 8.5, 'syn_flag_count': 1, 'unique_dst_ports': 1
        },
        "Scenario 2: Port Scan / Reconnaissance": {
            'flow_duration': 200, 'packet_rate': 45.0, 'syn_flag_count': 5, 'unique_dst_ports': 40
        },
        "Scenario 3: Denial-of-Service (DoS)": {
            'flow_duration': 300, 'packet_rate': 1500.0, 'syn_flag_count': 850, 'unique_dst_ports': 1
        },
        "Scenario 4: Additional Attack (Brute-Force / Suspicious)": {
            'flow_duration': 12000, 'packet_rate': 120.0, 'syn_flag_count': 15, 'unique_dst_ports': 2
        },
        "Scenario 5: Ambiguous / Borderline Case": {
            'flow_duration': 400, 'packet_rate': 320.0, 'syn_flag_count': 45, 'unique_dst_ports': 3
        }
    }

    # Execute detection for each scenario
    for name, raw_data in scenarios.items():
        print(f"[*] Testing {name}...")
        
        # Step 1: Extract features
        df = pd.DataFrame([raw_data])
        features = extract_features(df).iloc[0].to_dict()
        
        # Step 2: Run through detection engine
        result = engine.analyze_traffic(features)
        
        # Print structured explainable output
        print(f"    -> Prediction : {result['prediction']}")
        print(f"    -> Severity   : {result['severity']}")
        print(f"    -> Confidence : {result['confidence']}")
        print(f"    -> Explanation: {result['explanation']}\n")

if __name__ == "__main__":
    run_mandatory_scenarios()