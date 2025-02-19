# Endec

A simple cross-platform tool for encrypting and decrypting files using **AES-256-GCM**.

## Features
- **AES-256-GCM Encryption** 
- **Password-based encryption & decryption** using PBKDF2 key derivation
- **Automatic filename handling** (`file.txt` → `file_txt.enc`, and vice versa)
- **Drag-and-drop filename support** (removes unwanted quotation marks)
- **Cross-platform compatibility** (Windows, macOS, Linux)
- **Up to 5 password attempts for decryption** (after that Endec must be restarted)
- **Automatic deletion of original files after successful encryption/decryption**

---

## Installation

### 1. Clone the repository
```sh
git clone https://github.com/stmjan/endec.git
cd endec
```

### 2. Create a Virtual Environment
#### **Windows**:
```sh
python -m venv venv
venv\Scripts\activate
```
#### **Linux/macOS**:
```sh
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```sh
pip install -r requirements.txt
```

---

## Usage

### **Windows** (Double-click to run)
Use `endec_windows.bat` to automatically activate the environment and launch the program:
```sh
double-click endec_windows.bat
```
Or run manually:
```sh
venv\Scripts\activate
python endec.py
```

### **Linux/macOS** (Double-click or Run in Terminal)
```sh
./start_linux.sh
```
Or run manually:
```sh
source venv/bin/activate
python3 endec.py
```

---

## How It Works

### **Encrypt a File**
1. Run the program
2. Enter the file path (or drag and drop it into the console)
3. Enter a password (displayed in plain text)
4. The file will be encrypted and the **original file DELETED!!!**

### **Decrypt a File**
1. Run the program
2. Enter the `.enc` file path (or drag and drop it into the console)
3. Enter the correct password (5 attempts allowed)
4. The file will be decrypted and the `.enc` file deleted

---

## Example
**Encryption:**
```sh
python endec.py
Filename: my_secret.txt
Password: password123
```
_Result: `my_secret.txt` → `my_secret_txt.enc`_

**Decryption:**
```sh
python endec.py
Filename: my_secret_txt.enc
Password: password123
```
_Result: `my_secret_txt.enc` → `my_secret.txt`_

---

## IMPORTANT NOTES
- Unlike the above example, use a **strong password** to ensure better security!
- Make sure to **backup your passwords** (decryption is impossible without the correct password)
- If the wrong password is entered 5 times, decryption fails and endec must be restarted
- The `.enc` file remains unchanged if decryption fails

---

## License
MIT License

---

## Author
Developed by **stmjan**

