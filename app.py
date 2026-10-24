import streamlit as st
import os
import pandas as pd
from src.detection_engine import HybridIDSEngine

st.set_page_config(page_title="AI-Powered IDS Dashboard", page_icon="🛡️", layout="wide")

st.title("🛡️ AI-Powered Intrusion Detection System (IDS)")
st.markdown("Real-time network traffic analysis using a Hybrid Rule-Based & Random Forest Machine Learning Engine.")

# Initialize the IDS Engine
model_path = "models/ids_model.pkl"
dataset_path = os.path.join("archive", "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")


@st.cache_resource
def load_engine():
    # If model exists, load it; otherwise train it from dataset
    return HybridIDSEngine(model_path=model_path, dataset_path=dataset_path if not os.path.exists(model_path) else None)


with st.spinner("Initializing Hybrid IDS Engine..."):
    engine = load_engine()

st.sidebar.header("🛜 Network Flow Parameters")
flow_duration = st.sidebar.slider("Flow Duration (ms)", 0, 10000, 500)
packet_rate = st.sidebar.slider("Packet Rate (pkts/sec)", 0.0, 5000.0, 1200.0)
syn_flag_count = st.sidebar.slider("SYN Flag Count", 0, 1000, 600)
unique_dst_ports = st.sidebar.slider("Unique Destination Ports", 1, 100, 1)

if st.button("🔍 Analyze Traffic Flow", type="primary"):
    test_sample = {
        'flow_duration': flow_duration,
        'packet_rate': packet_rate,
        'syn_flag_count': syn_flag_count,
        'unique_dst_ports': unique_dst_ports
    }

    result = engine.analyze_traffic(test_sample)

    st.markdown("---")
    st.subheader("📊 Analysis Results")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric(label="Prediction", value=result['prediction'])
    with col2:
        st.metric(label="Severity Level", value=result['severity'])
    with col3:
        st.metric(label="Confidence Score", value=f"{result['confidence'] * 100:.1f}%")

    st.markdown("### 📝 Detailed Explanation")
    if result['severity'] == "HIGH":
        st.error(result['explanation'])
    elif result['severity'] == "MEDIUM":
        st.warning(result['explanation'])
    else:
        st.success(result['explanation'])