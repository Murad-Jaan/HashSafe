import streamlit as st
import hashlib
import io
from pathlib import Path
from utils.hash_utils import (
    hash_text, hash_file, detect_hash_type, 
    verify_hash, generate_qr_code, get_all_algorithms
)
from utils.file_utils import (
    save_file_hash, check_file_integrity, 
    detect_hash_collision, export_hashes
)
from utils.password_utils import (
    analyze_password_strength, check_leaked_password
)

# Page config
st.set_page_config(
    page_title="HashSafe - Cybersecurity Toolkit",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for dark theme with neon styling
st.markdown("""
<style>
    .main {
        background-color: #0e1117;
    }
    .stButton>button {
        background-color: #00ff41;
        color: #0e1117;
        font-weight: bold;
        border-radius: 5px;
        border: 2px solid #00ff41;
    }
    .stButton>button:hover {
        background-color: #0e1117;
        color: #00ff41;
    }
    h1, h2, h3 {
        color: #00ff41;
        text-shadow: 0 0 10px #00ff41;
    }
    .warning-box {
        background-color: #ff4444;
        padding: 10px;
        border-radius: 5px;
        color: white;
    }
    .success-box {
        background-color: #00ff41;
        padding: 10px;
        border-radius: 5px;
        color: #0e1117;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'hash_history' not in st.session_state:
    st.session_state.hash_history = []

# Sidebar
with st.sidebar:
    st.image("https://img.icons8.com/nolan/96/lock.png", width=100)
    st.title("🔒 HashSafe")
    st.markdown("---")
    st.markdown("**Advanced Hashing & Security Toolkit**")
    st.markdown("Professional-grade cryptographic utilities")
    
    if st.button("Clear All History", type="secondary"):
        st.session_state.hash_history = []
        st.success("History cleared!")

# Main title
st.title("🔐 HashSafe: Advanced Hashing Utility")
st.markdown("### Professional Cybersecurity Toolkit")

# Tabs
tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
    "📝 Text Hashing", 
    "📂 File Hashing", 
    "🔍 Hash Detection",
    "✅ Hash Verification",
    "🔐 Password Security",
    "📊 History",
    "🛡️ File Integrity"
])

# TAB 1: Text Hashing
with tab1:
    st.header("Text Hashing")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        text_input = st.text_area("Enter text to hash:", height=150)
        algorithms = st.multiselect(
            "Select hashing algorithms:",
            get_all_algorithms(),
            default=["SHA256", "SHA512"]
        )
    
    with col2:
        if st.button("🔄 Clear Input", key="clear_text"):
            st.rerun()
    
    if st.button("Generate Hashes", type="primary"):
        if text_input and algorithms:
            results = {}
            for algo in algorithms:
                hash_result = hash_text(text_input, algo)
                results[algo] = hash_result
                
                # Weak hash warning
                if algo in ["MD5", "SHA1"]:
                    st.markdown(f'<div class="warning-box">⚠️ {algo} is cryptographically weak and not recommended for security purposes!</div>', unsafe_allow_html=True)
                
                st.code(f"{algo}: {hash_result}", language="text")
                
                # Add to history
                st.session_state.hash_history.append({
                    "type": "text",
                    "algorithm": algo,
                    "hash": hash_result,
                    "input": text_input[:50] + "..." if len(text_input) > 50 else text_input
                })
            
            # QR Code generation
            st.subheader("Generate QR Code")
            qr_algo = st.selectbox("Select hash for QR:", algorithms)
            if st.button("Generate QR Code"):
                qr_img = generate_qr_code(results[qr_algo])
                st.image(qr_img, caption=f"{qr_algo} QR Code", width=300)
            
            # Export options
            st.subheader("Export Results")
            export_format = st.selectbox("Format:", ["TXT", "CSV", "JSON"])
            if st.button("Download"):
                export_data = export_hashes(results, export_format)
                st.download_button(
                    label=f"Download as {export_format}",
                    data=export_data,
                    file_name=f"hashes.{export_format.lower()}",
                    mime="text/plain"
                )
        else:
            st.warning("Please enter text and select at least one algorithm.")

# TAB 2: File Hashing
with tab2:
    st.header("File Hashing")
    
    uploaded_files = st.file_uploader(
        "Upload files to hash:",
        accept_multiple_files=True,
        type=None
    )
    
    file_algorithms = st.multiselect(
        "Select algorithms:",
        get_all_algorithms(),
        default=["SHA256"],
        key="file_algo"
    )
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Hash Files", type="primary"):
            if uploaded_files and file_algorithms:
                all_file_hashes = {}
                
                for file in uploaded_files:
                    st.subheader(f"📄 {file.name}")
                    file_hashes = {}
                    
                    for algo in file_algorithms:
                        file_hash = hash_file(file, algo)
                        file_hashes[algo] = file_hash
                        st.code(f"{algo}: {file_hash}", language="text")
                        
                        # Save for integrity monitoring
                        save_file_hash(file.name, algo, file_hash)
                        
                        # Add to history
                        st.session_state.hash_history.append({
                            "type": "file",
                            "filename": file.name,
                            "algorithm": algo,
                            "hash": file_hash
                        })
                    
                    all_file_hashes[file.name] = file_hashes
                
                # Collision detection
                if len(uploaded_files) > 1:
                    st.subheader("🔍 Collision Detection")
                    collisions = detect_hash_collision(all_file_hashes)
                    if collisions:
                        st.error(f"⚠️ Hash collision detected! {collisions}")
                    else:
                        st.success("✅ No collisions detected - all files are unique")
            else:
                st.warning("Please upload files and select algorithms.")
    
    with col2:
        if st.button("🔄 Clear Files", key="clear_files"):
            st.rerun()

# TAB 3: Hash Detection
with tab3:
    st.header("Hash Type Detection")
    st.markdown("Identify the type of an unknown hash")
    
    unknown_hash = st.text_input("Enter hash to identify:")
    
    if st.button("Detect Hash Type", type="primary"):
        if unknown_hash:
            detected_type = detect_hash_type(unknown_hash)
            if detected_type:
                st.markdown(f'<div class="success-box">✅ Detected: {detected_type}</div>', unsafe_allow_html=True)
            else:
                st.error("❌ Unable to determine hash type")
        else:
            st.warning("Please enter a hash")

# TAB 4: Hash Verification
with tab4:
    st.header("Hash Verification")
    st.markdown("Verify if text/file matches a given hash")
    
    verify_type = st.radio("Verify:", ["Text", "File"])
    
    if verify_type == "Text":
        verify_text = st.text_area("Enter text:", height=100)
        verify_hash = st.text_input("Enter expected hash:")
        verify_algo = st.selectbox("Algorithm:", get_all_algorithms(), key="verify_algo")
        
        if st.button("Verify Hash", type="primary"):
            if verify_text and verify_hash and verify_algo:
                is_match = verify_hash(verify_text, verify_hash, verify_algo)
                if is_match:
                    st.markdown('<div class="success-box">✅ MATCH! Hash verified successfully</div>', unsafe_allow_html=True)
                else:
                    st.error("❌ NO MATCH! Hash verification failed")
            else:
                st.warning("Please fill all fields")
    else:
        verify_file = st.file_uploader("Upload file:", key="verify_file")
        verify_hash_file = st.text_input("Enter expected hash:", key="verify_hash_file")
        verify_algo_file = st.selectbox("Algorithm:", get_all_algorithms(), key="verify_algo_file")
        
        if st.button("Verify File Hash", type="primary"):
            if verify_file and verify_hash_file and verify_algo_file:
                computed_hash = hash_file(verify_file, verify_algo_file)
                if computed_hash.lower() == verify_hash_file.lower():
                    st.markdown('<div class="success-box">✅ MATCH! File verified successfully</div>', unsafe_allow_html=True)
                else:
                    st.error("❌ NO MATCH! File verification failed")
            else:
                st.warning("Please provide file, hash, and algorithm")

# TAB 5: Password Security
with tab5:
    st.header("Password Security Analysis")
    
    password = st.text_input("Enter password to analyze:", type="password")
    
    if st.button("Analyze Password", type="primary"):
        if password:
            strength = analyze_password_strength(password)
            
            st.subheader("Strength Analysis")
            st.metric("Strength Score", f"{strength['score']}/100")
            st.metric("Entropy", f"{strength['entropy']:.2f} bits")
            
            # Visual strength indicator
            if strength['score'] >= 80:
                st.success("🟢 Strong password!")
            elif strength['score'] >= 50:
                st.warning("🟡 Moderate password - consider strengthening")
            else:
                st.error("🔴 Weak password - please use a stronger password")
            
            st.markdown("**Recommendations:**")
            for rec in strength['recommendations']:
                st.write(f"• {rec}")
            
            # Leaked password check
            st.subheader("Leaked Password Check")
            is_leaked = check_leaked_password(password)
            if is_leaked:
                st.error("⚠️ WARNING: This password appears in known data breaches!")
            else:
                st.success("✅ Password not found in known breach databases")
        else:
            st.warning("Please enter a password")

# TAB 6: History
with tab6:
    st.header("Hash History")
    
    if st.session_state.hash_history:
        # Search functionality
        search_term = st.text_input("🔍 Search history:", "")
        
        filtered_history = st.session_state.hash_history
        if search_term:
            filtered_history = [
                h for h in st.session_state.hash_history 
                if search_term.lower() in str(h).lower()
            ]
        
        st.write(f"Showing {len(filtered_history)} results")
        
        for idx, entry in enumerate(reversed(filtered_history)):
            with st.expander(f"{entry['type'].upper()} - {entry['algorithm']} (#{len(filtered_history)-idx})"):
                for key, value in entry.items():
                    st.write(f"**{key.capitalize()}:** {value}")
        
        # Export all history
        if st.button("Export All History"):
            history_str = "\n".join([str(h) for h in st.session_state.hash_history])
            st.download_button(
                "Download History",
                history_str,
                file_name="hash_history.txt",
                mime="text/plain"
            )
    else:
        st.info("No hash history yet. Start hashing to build your history!")

# TAB 7: File Integrity Monitoring
with tab7:
    st.header("File Integrity Monitoring")
    st.markdown("Track file changes by comparing current hash with stored hash")
    
    integrity_file = st.file_uploader("Upload file to check:", key="integrity_file")
    integrity_algo = st.selectbox("Algorithm:", get_all_algorithms(), key="integrity_algo")
    
    if st.button("Check Integrity", type="primary"):
        if integrity_file:
            result = check_file_integrity(integrity_file.name, integrity_file, integrity_algo)
            
            if result['status'] == 'match':
                st.markdown('<div class="success-box">✅ File integrity verified - no changes detected</div>', unsafe_allow_html=True)
                st.code(f"Current hash: {result['current_hash']}")
            elif result['status'] == 'mismatch':
                st.error("⚠️ FILE TAMPERING DETECTED! Hash mismatch!")
                st.code(f"Expected: {result['stored_hash']}\nCurrent:  {result['current_hash']}")
            else:
                st.info("ℹ️ No previous hash found. Hash has been stored for future verification.")
                st.code(f"Stored hash: {result['current_hash']}")
        else:
            st.warning("Please upload a file")

# Footer
st.markdown("---")
st.markdown(
    "<div style='text-align: center; color: #00ff41;'>"
    "🔒 HashSafe v1.0 | Professional Cybersecurity Toolkit | "
    "Built with Streamlit"
    "</div>",
    unsafe_allow_html=True
)