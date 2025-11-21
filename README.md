# 🔒 HashSafe: Advanced Hashing Utility & Cybersecurity Toolkit

**HashSafe** is a professional cybersecurity tool for hashing text and files, verifying integrity, detecting hash types, analyzing password security, and generating QR codes.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Streamlit](https://img.shields.io/badge/Streamlit-1.28+-red.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

## ✨ Features

### Core Hashing & Security
- **Multi-algorithm hashing**: MD5, SHA1, SHA224, SHA256, SHA384, SHA512, SHA3 variants, BLAKE2b, BLAKE2s, SHAKE128, SHAKE256
- **Text and File hashing** with batch processing support
- **Hash type detection** - identify unknown hash types
- **Hash verification** - verify text/files against known hashes
- **QR code generation** for hashes
- **Weak hash warnings** for MD5/SHA1

### File Security
- **File integrity monitoring** - detect file tampering
- **Hash collision detection** between multiple files
- **Multi-file batch processing**

### Password Security
- **Password strength analysis** based on entropy
- **Leaked password detection** (Have I Been Pwned style)
- **Security recommendations** for weak passwords

### User Experience
- **Dark theme UI** with professional neon styling
- **Download capabilities**: TXT, CSV, JSON export formats
- **Session history** with search and filter
- **Clear buttons** for easy reset
- **Professional interface** designed for security professionals

## 📦 Installation

### Quick Start

```bash
# Clone the repository
git clone https://github.com/YourUsername/HashSafe.git
cd HashSafe

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the application
streamlit run hasher.py
```

### Docker Deployment (Optional)

```bash
docker build -t hashsafe .
docker run -p 8501:8501 hashsafe
```

## 📁 Project Structure

```
HashSafe/
│
├── hasher.py             # Main Streamlit application
├── requirements.txt      # Python dependencies
├── utils/
│   ├── hash_utils.py     # Hashing, detection, verification, QR
│   ├── file_utils.py     # File handling, integrity checks
│   ├── password_utils.py # Password strength & leak checking
│   └── encryption.py     # (Optional) AES encryption
├── data/
│   └── leaked_passwords.txt  # Common leaked password hashes
├── assets/
│   ├── logo.png
│   └── style.css
├── history/              # Hash history storage
├── README.md
└── Dockerfile            # Container configuration
```

## 🚀 Usage

### Text Hashing
1. Navigate to the **Text Hashing** tab
2. Enter your text
3. Select one or more hashing algorithms
4. Click **Generate Hashes**
5. Optionally generate QR codes or export results

### File Hashing
1. Go to the **File Hashing** tab
2. Upload one or multiple files
3. Select algorithms
4. Click **Hash Files**
5. System automatically checks for hash collisions

### Hash Detection
1. Open **Hash Detection** tab
2. Paste an unknown hash
3. Click **Detect Hash Type**
4. System identifies the hash algorithm

### Password Analysis
1. Visit **Password Security** tab
2. Enter password (input is masked)
3. Click **Analyze Password**
4. Review strength score, entropy, and recommendations
5. Check if password appears in breach databases

### File Integrity Monitoring
1. Go to **File Integrity** tab
2. Upload a file to monitor
3. System stores hash for comparison
4. Re-upload same file later to detect tampering

## 🔧 Configuration

### Adding Custom Leaked Passwords

Create `data/leaked_passwords.txt` with MD5 hashes (one per line):

```
5f4dcc3b5aa765d61d8327deb882cf99
e10adc3949ba59abbe56e057f20f883e
```

### Customizing Algorithms

Edit `utils/hash_utils.py` to add/remove algorithms from `get_all_algorithms()`.

## 🛡️ Security Notes

- **MD5 and SHA1** are cryptographically broken - use SHA256+ for security
- **Password storage**: Never store plaintext passwords
- **File integrity**: Regular monitoring detects unauthorized modifications
- **Leaked passwords**: Database should be updated regularly

## 📊 Screenshots

*Add screenshots of your application here*

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with [Streamlit](https://streamlit.io/)
- Hashing algorithms from Python's `hashlib`
- QR code generation via `qrcode` library
- Inspired by professional cybersecurity tools

## 📧 Contact

Your Name - [@YourTwitter](https://twitter.com/YourTwitter)

Project Link: [https://github.com/YourUsername/HashSafe](https://github.com/YourUsername/HashSafe)

---

**⚠️ Disclaimer**: This tool is for educational and professional security purposes only. Always follow responsible disclosure practices and legal guidelines.