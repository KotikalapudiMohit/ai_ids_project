import pandas as pd
import numpy as np

def extract_features(df):
    """
    Extracts and normalizes features from raw CICIDS2017 format or custom tabular data.
    """
    processed_df = pd.DataFrame()
    
    # CICIDS2017 uses exact column naming conventions with leading/trailing spaces sometimes
    # We use .get() with multiple fallbacks to ensure compatibility
    processed_df['flow_duration'] = df.get('Flow Duration', df.get('flow_duration', 0))
    
    fwd_pkts = df.get('Total Fwd Packets', df.get('total_fwd_packets', 0))
    bwd_pkts = df.get('Total Backward Packets', df.get('total_bwd_packets', 0))
    processed_df['total_packets'] = fwd_pkts + bwd_pkts
    
    # Calculate packet rate safely
    duration = processed_df['flow_duration']
    processed_df['packet_rate'] = np.where(
        duration > 0, 
        processed_df['total_packets'] / (duration / 1000000.0), 
        0
    )
    
    processed_df['syn_flag_count'] = df.get('SYN Flag Count', df.get('syn_flag_count', 0))
    
    # CICIDS tracks destination ports; if missing, use standard fallback
    processed_df['unique_dst_ports'] = df.get('Destination Port', df.get('unique_dst_ports', 1))
    
    # Retain the label column if present in training data
    if 'Label' in df.columns:
        processed_df['Label'] = df['Label']
    elif ' Label' in df.columns:  # CICIDS datasets often have a leading space in ' Label'
        processed_df['Label'] = df[' Label']
        
    return processed_df