# BlackOutPDF
![Logo BlackOutPDF](./images/BlackOutPDF.png)

**The  PDF Redaction Tool with Advanced RSA Content Protection**

BlackOutPDF introduces a groundbreaking approach to document security: **RSA Content Encryption**. Unlike traditional tools that simply password-protect PDFs, BlackOutPDF encrypts the actual redacted content itself, allowing universal document access while restricting content restoration to authorized users only.

##  Features :

### **RSA Content Encryption Technology**
- **Universal Access**: Anyone can open and read the redacted PDF
- **Selective Restoration**: Only private key holders can un-redact content
- **Content-Level Security**: Encrypts redaction data, not document access

### **Advanced Redaction Tools**
- **Multiple Shapes**: Rectangles, polygons, freehand drawing
- **Visual Interface**: Intuitive Qt5-based GUI with real-time preview
- **Smart Selection**: Intelligent area detection and selection
- **Reversible Process**: Complete content preservation with encryption

### **Professional Security**
- **RSA Key Management**: Generate, import, and manage RSA key pairs
- **Hybrid Encryption**: RSA + AES for optimal security and performance
- **Integrity Verification**: SHA256 checksums ensure data integrity

## Why Choose BlackOutPDF?

### **Traditional Redaction Problems Solved**
- **Standard tools**: Permanent content destruction
- **Password protection**: All-or-nothing access control

### **BlackOutPDF Advantages**
- **Reversible redaction**: Original content preserved and encrypted
- **Granular control**: Individual content restoration by authorized users
- **Future-proof**: Content remains accessible to key holders indefinitely

## Quick Start Guide

### Installation
```bash
# Clone or download BlackOutPDF
cd BlackOutPDF2

python3 -m venv venv
source venv/bin/activate
# or
# .\venv\Scripts\activate
# Install dependencies
pip install -r requirements.txt

# Launch application
python3 BOPDF2.py.py
```

### Basic Workflow
1. **Load Document**: Open your PDF file
2. **Generate Keys**: Create RSA key pair or import existing keys
3. **Mark Areas**: Select content to redact using drawing tools
4. **Export Encrypted**: Save with RSA public key encryption
5. **Distribute**: Share redacted PDF - anyone can read it
6. **Restore Content**: Use private key to decrypt and restore original content

### **Encryption Standards**
- **RSA Key Sizes**: 2048, 3072, 4096 bits
- **Symmetric Encryption**: AES-256-GCM
- **Hash Functions**: SHA-256, MD5 verification
- **Key Derivation**: PBKDF2 with random salts

### **Data Protection**
- **Content Isolation**: Redacted areas completely destroyed in visible layer
- **Encrypted Storage**: Original content encrypted with hybrid RSA+AES
- **Integrity Verification**: Multiple checksum validation layers
- **Secure Cleanup**: Temporary data securely wiped after operations

### **Dependencies**
- **PyQt5**: Modern GUI framework
- **PyMuPDF**: Professional PDF processing
- **Cryptography**: Military-grade encryption
- **Pillow**: Advanced image processing
- **NumPy**: High-performance data operations



