from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from Crypto.Cipher import DES, AES, DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

app = Flask(__name__, template_folder='templates', static_folder='static')
CORS(app)

# Serve the main HTML page
@app.route("/")
def index():
    return render_template("index.html")

# One-time pad encryption (unchanged)
def otp_encrypt(message, key):
    if len(key) < len(message):
        raise ValueError("Key must be at least as long as the message.")
    return ''.join(chr(ord(m) ^ ord(k)) for m, k in zip(message, key))

def otp_decrypt(encrypted_message, key):
    return otp_encrypt(encrypted_message, key)  # OTP is symmetric

def validate_des_key(key):
    """Ensure the key is valid for DES."""
    if isinstance(key, str):  # If the key is a string, encode it
        key = key.encode('utf-8')
    if len(key) != 8:
        raise ValueError("DES key must be exactly 8 bytes long.")  # Raise error for invalid key length
    return key

# DES encryption and decryption (using CBC mode)
def des_encrypt(key, plaintext):
    key = validate_des_key(key)  # Validate the key
    cipher = DES.new(key, DES.MODE_CBC)  # Use CBC mode
    iv = cipher.iv  # Initialization vector
    padded_text = pad(plaintext.encode('utf-8'), DES.block_size)  # PKCS7 padding
    encrypted = cipher.encrypt(padded_text)
    return base64.b64encode(iv + encrypted).decode('utf-8')  # Prepend IV to ciphertext

def des_decrypt(key, encrypted):
    key = validate_des_key(key)  # Validate the key
    encrypted = base64.b64decode(encrypted.encode('utf-8'))
    iv = encrypted[:DES.block_size]  # Extract IV
    cipher = DES.new(key, DES.MODE_CBC, iv)  # Use CBC mode with IV
    decrypted = unpad(cipher.decrypt(encrypted[DES.block_size:]), DES.block_size)  # Remove padding
    return decrypted.decode('utf-8')

# AES encryption and decryption (using CBC mode)
def aes_encrypt(key, plaintext):
    key = key.ljust(16)[:16].encode('utf-8')  # Ensure key is 16 bytes
    cipher = AES.new(key, AES.MODE_CBC)  # Use CBC mode
    iv = cipher.iv  # Initialization vector
    padded_text = pad(plaintext.encode('utf-8'), AES.block_size)  # PKCS7 padding
    encrypted = cipher.encrypt(padded_text)
    return base64.b64encode(iv + encrypted).decode('utf-8')  # Prepend IV to ciphertext

def aes_decrypt(key, encrypted):
    key = key.ljust(16)[:16].encode('utf-8')  # Ensure key is 16 bytes
    encrypted = base64.b64decode(encrypted.encode('utf-8'))
    iv = encrypted[:AES.block_size]  # Extract IV
    cipher = AES.new(key, AES.MODE_CBC, iv)  # Use CBC mode with IV
    decrypted = unpad(cipher.decrypt(encrypted[AES.block_size:]), AES.block_size)  # Remove padding
    return decrypted.decode('utf-8')

# 3DES encryption and decryption with key validation
def validate_des3_key(key):
    """Ensure the key is valid for Triple DES."""
    if isinstance(key, str):  # If the key is a string, encode it
        key = key.encode('utf-8')
    if len(key) < 16:
        raise ValueError("Triple DES key must be at least 16 bytes long.")  # Raise error for short keys
    if len(key) > 24:
        key = key[:24]  # Truncate to 24 bytes if too long
    elif 16 < len(key) < 24:
        key = key.ljust(24, b'\0')  # Pad to 24 bytes if between 16 and 24 bytes
    try:
        DES3.adjust_key_parity(key)  # Ensure the key has valid parity
    except ValueError:
        raise ValueError("Invalid Triple DES key. Ensure it does not degenerate to single DES.")
    return key

def des3_encrypt(key, plaintext):
    key = validate_des3_key(key)  # Validate the key
    cipher = DES3.new(key, DES3.MODE_CBC)  # Use CBC mode
    iv = cipher.iv  # Initialization vector
    padded_text = pad(plaintext.encode('utf-8'), DES3.block_size)  # PKCS7 padding
    encrypted = cipher.encrypt(padded_text)
    return base64.b64encode(iv + encrypted).decode('utf-8')  # Prepend IV to ciphertext

def des3_decrypt(key, encrypted):
    key = validate_des3_key(key)  # Validate the key
    encrypted = base64.b64decode(encrypted.encode('utf-8'))
    iv = encrypted[:DES3.block_size]  # Extract IV
    cipher = DES3.new(key, DES3.MODE_CBC, iv)  # Use CBC mode with IV
    decrypted = unpad(cipher.decrypt(encrypted[DES3.block_size:]), DES3.block_size)  # Remove padding
    return decrypted.decode('utf-8')

def validate_aes_key(key):
    """Ensure the key is valid for AES."""
    if len(key) < 16:
        raise ValueError("AES key must be at least 16 bytes long.")
    return key.ljust(16)[:16]  # Pad or truncate to 16 bytes

@app.errorhandler(Exception)
def handle_exception(e):
    """Global error handler for unexpected exceptions."""
    return jsonify({'error': str(e)}), 500

@app.route('/api/aes/encrypt', methods=['POST'])
def api_encrypt_aes():
    try:
        data = request.json
        key = data.get('key')
        plaintext = data.get('plaintext')
        if not key or not plaintext:
            return jsonify({'error': 'Key and plaintext are required.'}), 400
        key = validate_aes_key(key)  # Validate AES key
        result = aes_encrypt(key, plaintext)
        return jsonify({'encrypted_text': result})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/aes/decrypt', methods=['POST'])
def api_decrypt_aes():
    try:
        data = request.json
        key = data.get('key')
        encrypted = data.get('encrypted')
        if not key or not encrypted:
            return jsonify({'error': 'Key and encrypted text are required.'}), 400
        key = validate_aes_key(key)  # Validate AES key
        result = aes_decrypt(key, encrypted)
        return jsonify({'decrypted_text': result})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/otp/encrypt', methods=['POST'])
def api_encrypt_otp():
    try:
        data = request.json
        plaintext = data.get('plaintext')
        key = data.get('key')
        if not plaintext or not key:
            return jsonify({'error': 'Plaintext and key are required.'}), 400
        if len(key) < len(plaintext):  # Validate key length
            return jsonify({'error': 'Key must be at least as long as the message.'}), 400
        result = otp_encrypt(plaintext, key)
        return jsonify({'encrypted_text': result})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/otp/decrypt', methods=['POST'])
def api_decrypt_otp():
    try:
        data = request.json
        encrypted = data.get('encrypted')
        key = data.get('key')
        if not encrypted or not key:
            return jsonify({'error': 'Encrypted text and key are required.'}), 400
        if len(key) < len(encrypted):  # Validate key length
            return jsonify({'error': 'Key must be at least as long as the message.'}), 400
        result = otp_decrypt(encrypted, key)
        return jsonify({'decrypted_text': result})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/3des/encrypt', methods=['POST'])
def api_encrypt_3des():
    try:
        data = request.json
        key = data.get('key')
        plaintext = data.get('plaintext')
        if not key or not plaintext:
            return jsonify({'error': 'Key and plaintext are required.'}), 400
        key = validate_des3_key(key)  # Validate Triple DES key
        result = des3_encrypt(key, plaintext)
        return jsonify({'encrypted_text': result})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/3des/decrypt', methods=['POST'])
def api_decrypt_3des():
    try:
        data = request.json
        key = data.get('key')
        encrypted = data.get('encrypted')
        if not key or not encrypted:
            return jsonify({'error': 'Key and encrypted text are required.'}), 400
        key = validate_des3_key(key)  # Validate Triple DES key
        result = des3_decrypt(key, encrypted)
        return jsonify({'decrypted_text': result})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/des/encrypt', methods=['POST'])
def api_encrypt_des():
    try:
        data = request.json
        key = data.get('key')
        plaintext = data.get('plaintext')
        if not key or not plaintext:
            return jsonify({'error': 'Key and plaintext are required.'}), 400
        key = validate_des_key(key)  # Validate DES key
        result = des_encrypt(key, plaintext)
        return jsonify({'encrypted_text': result})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400  # Return error for invalid key
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/des/decrypt', methods=['POST'])
def api_decrypt_des():
    try:
        data = request.json
        key = data.get('key')
        encrypted = data.get('encrypted')
        if not key or not encrypted:
            return jsonify({'error': 'Key and encrypted text are required.'}), 400
        key = validate_des_key(key)  # Validate DES key
        result = des_decrypt(key, encrypted)
        return jsonify({'decrypted_text': result})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400  # Return error for invalid key
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)