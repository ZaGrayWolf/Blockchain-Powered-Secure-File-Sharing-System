# app.py
import streamlit as st
import os
import json
from datetime import datetime
from crypto_module import encrypt_file, decrypt_file, safe_filename_hash

# ---------------------------
# CONFIGURATION VARIABLES
# ---------------------------
MAX_FILE_SIZE_MB = 50
ALLOWED_EXTENSIONS = ['.pdf', '.txt', '.docx', '.jpg', '.png', '.xlsx']

UPLOAD_FOLDER = "uploads"
DATA_FOLDER = "data"
LEDGER_FILE = os.path.join(DATA_FOLDER, "blockchain_ledger.json")
METADATA_FILE = os.path.join(DATA_FOLDER, "file_metadata.json")

DEMO_USER = "demo_user"
PASSWORD_MIN_LENGTH = 6

PAGE_TITLE = "Blockchain File Sharing POC"
PAGE_ICON = "🔐"
LAYOUT = "wide"

# Ensure folders exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(DATA_FOLDER, exist_ok=True)

# Initialize JSON files if missing
for f in [METADATA_FILE, LEDGER_FILE]:
    if not os.path.exists(f):
        with open(f, "w") as fp:
            fp.write("{}")

# ---------------------------
# HELPER FUNCTIONS
# ---------------------------

def load_json(file_path):
    with open(file_path, "r") as f:
        return json.load(f)

def save_json(file_path, data):
    with open(file_path, "w") as f:
        json.dump(data, f, indent=4)

def reset_demo():
    """Reset metadata and blockchain ledger, then refresh the app."""
    for f in [METADATA_FILE, LEDGER_FILE]:
        if os.path.exists(f):
            with open(f, "w") as fp:
                fp.write("{}")  # empty JSON
    for key in st.session_state.keys():
        del st.session_state[key]
    st.success("✅ Metadata and ledger reset successfully!")
    try:
        st.experimental_rerun()
    except AttributeError:
        st.info("Please manually refresh the page to complete reset.")

def add_block(file_hash, filename, action="UPLOAD"):
    """Add a simulated blockchain entry."""
    ledger = load_json(LEDGER_FILE)
    chain = ledger.get("chain", [])
    block_number = len(chain) + 1
    timestamp = datetime.utcnow().timestamp()
    datetime_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    prev_hash = chain[-1]["block_hash"] if chain else "0"*64
    block_hash = safe_filename_hash(f"{file_hash}{timestamp}{prev_hash}".encode())

    block = {
        "block_number": block_number,
        "timestamp": timestamp,
        "datetime": datetime_str,
        "previous_hash": prev_hash,
        "transaction": {
            "file_hash": file_hash,
            "filename": filename,
            "action": action,
            "user": DEMO_USER
        },
        "block_hash": block_hash
    }

    chain.append(block)
    ledger["chain"] = chain
    ledger["block_count"] = len(chain)
    save_json(LEDGER_FILE, ledger)

# ---------------------------
# STREAMLIT APP
# ---------------------------

st.set_page_config(page_title=PAGE_TITLE, page_icon=PAGE_ICON, layout=LAYOUT)
st.title(PAGE_TITLE)

# ---------------------------
# SIDEBAR
# ---------------------------
st.sidebar.header("Settings")
if st.sidebar.button("Reset Metadata & Ledger"):
    reset_demo()

# ---------------------------
# PAGE NAVIGATION
# ---------------------------
page = st.sidebar.radio("Navigation", ["🔐 Upload File", "📥 Download File", "📊 Blockchain Logs"])

# ---------------------------
# PAGE 1: UPLOAD FILE
# ---------------------------
if page == "🔐 Upload File":
    st.header("Upload & Encrypt File")
    uploaded = st.file_uploader("Choose a file", type=[ext[1:] for ext in ALLOWED_EXTENSIONS])
    password = st.text_input("Enter encryption password", type="password")

    if st.button("Encrypt & Upload"):
        if uploaded is None:
            st.error("Please select a file to upload.")
        elif len(password) < PASSWORD_MIN_LENGTH:
            st.error(f"Password must be at least {PASSWORD_MIN_LENGTH} characters.")
        else:
            data = uploaded.read()
            if len(data) > MAX_FILE_SIZE_MB * 1024 * 1024:
                st.error(f"File exceeds {MAX_FILE_SIZE_MB} MB.")
            else:
                try:
                    # Encrypt
                    enc = encrypt_file(data, password)
                    file_hash = enc["file_hash"]
                    enc_filename = f"{file_hash}.enc"
                    with open(os.path.join(UPLOAD_FOLDER, enc_filename), "wb") as f:
                        f.write(enc["ciphertext"])

                    # Save metadata
                    metadata = load_json(METADATA_FILE)
                    metadata[file_hash] = {
                        "original_name": uploaded.name,
                        "encrypted_name": enc_filename,
                        "upload_time": enc["created_at"],
                        "file_size": len(data),
                        "salt": enc["salt"],
                        "iv": enc["iv"],
                        "tag": enc["tag"]
                    }
                    save_json(METADATA_FILE, metadata)

                    # Add blockchain log
                    add_block(file_hash, uploaded.name)

                    st.success(f"File '{uploaded.name}' encrypted and uploaded successfully!")
                except Exception as e:
                    st.error(f"Encryption failed: {str(e)}")

# ---------------------------
# PAGE 2: DOWNLOAD FILE
# ---------------------------
elif page == "📥 Download File":
    st.header("Download & Decrypt File")
    metadata = load_json(METADATA_FILE)
    if not metadata:
        st.info("No files available for download.")
    else:
        file_options = {v["original_name"]: k for k,v in metadata.items()}
        selected = st.selectbox("Select file", list(file_options.keys()))
        password = st.text_input("Enter decryption password", type="password")

        if st.button("Download File"):
            file_hash = file_options[selected]
            item = metadata[file_hash]
            enc_path = os.path.join(UPLOAD_FOLDER, item["encrypted_name"])

            if not os.path.exists(enc_path):
                st.error("Encrypted file not found.")
            else:
                try:
                    ciphertext = open(enc_path, "rb").read()
                    plaintext = decrypt_file(ciphertext, password, item["salt"], item["iv"], item["tag"])
                    st.download_button("Download Decrypted File", plaintext, file_name=item["original_name"])
                    st.success("File decrypted successfully!")
                    # Add blockchain log
                    add_block(file_hash, item["original_name"], action="DOWNLOAD")
                except ValueError as e:
                    st.error(str(e))

# ---------------------------
# PAGE 3: BLOCKCHAIN LOGS
# ---------------------------
elif page == "📊 Blockchain Logs":
    st.header("Blockchain Logs")
    ledger = load_json(LEDGER_FILE)
    chain = ledger.get("chain", [])
    if not chain:
        st.info("Blockchain is empty.")
    else:
        # Display logs in table
        import pandas as pd
        df = pd.DataFrame([{
            "Block#": b["block_number"],
            "File Hash": b["transaction"]["file_hash"],
            "Filename": b["transaction"]["filename"],
            "Action": b["transaction"]["action"],
            "User": b["transaction"]["user"],
            "Timestamp": b["datetime"]
        } for b in chain])
        st.dataframe(df)

        # Integrity verification
        if st.button("Verify Integrity"):
            valid = True
            for i, block in enumerate(chain):
                expected_prev = chain[i-1]["block_hash"] if i>0 else "0"*64
                if block["previous_hash"] != expected_prev:
                    valid = False
                    break
            if valid:
                st.success("✅ Blockchain integrity verified.")
            else:
                st.error("❌ Blockchain integrity compromised!")

        # Export CSV
        if st.button("Export Logs as CSV"):
            csv_data = df.to_csv(index=False).encode()
            st.download_button("Download CSV", csv_data, file_name="blockchain_logs.csv")
