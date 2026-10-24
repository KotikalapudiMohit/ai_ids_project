import os
import pandas as pd
from src.detection_engine import HybridIDSEngine

def main():
    print("=== STARTING FIRST LOCAL IDS TEST ===")
    
    # 1. Update this to match the EXACT filename of your downloaded Kaggle CSV inside 'data/'
    csv_filename = "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"  # <-- CHANGE THIS TO YOUR FILENAME
    csv_path = os.path.join("data", "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
    
    if not os.path.exists(csv_path):
        print(f"[!] Error: Could not find '{csv_path}'. Please make sure your CSV is inside the 'data/' folder.")
        return

    print(f"[*] Loading a sample of your dataset from {csv_path}...")
    df_sample = pd.read_csv(csv_path, nrows=5000)
    print(f"[+] Successfully loaded {len(df_sample)} rows.")

    print("[*] Initializing and training the Hybrid IDS Engine locally...")
    engine = HybridIDSEngine(dataset_path=csv_path)
    print("[+] Training complete! Model weights saved locally to models/ids_model.pkl")

    # 2. Test a sample prediction
    print("\n[*] Running a test prediction...")
    test_sample = {
        'flow_duration': 500,
        'packet_rate': 1200.0,
        'syn_flag_count': 600,
        'unique_dst_ports': 1
    }
    result = engine.analyze_traffic(test_sample)
    
    print("--- ANALYSIS RESULT ---")
    print(f"Prediction : {result['prediction']}")
    print(f"Severity   : {result['severity']}")
    print(f"Confidence : {result['confidence']}")
    print(f"Explanation: {result['explanation']}")

if __name__ == "__main__":
    main()
