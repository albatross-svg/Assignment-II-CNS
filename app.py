from flask import Flask, request, jsonify, render_template  
from Crypto.Cipher import DES, AES  
from Crypto.Random import get_random_bytes  
from Crypto.Protocol.KDF import PBKDF2  
import base64  
import os  

app = Flask(__name__)  

# One-time pad encryption  
def otp_encrypt(message: str, key: str) -> str:  
    if len(key) < len(message):
        raise ValueError("Key must be at least as long as the message.")  
    return ''.join(chr(ord(m) ^ ord(k)) for m, k in zip(message, key))  

def otp_decrypt(encrypted_message: str, key: str) -> str:  
    return otp_encrypt(encrypted_message, key)  

# DES encryption and decryption  
def des_encrypt(key: str, plaintext: str) -> str:  
    cipher = DES.new(key.ljust(8)[:8].encode('utf-8'), DES.MODE_ECB)  
    padded_text = plaintext + (8 - len(plaintext) % 8) * chr(8 - len(plaintext) % 8)  
    return base64.b64encode(cipher.encrypt(padded_text.encode('utf-8'))).decode('utf-8')  

def des_decrypt(key: str, encrypted: str) -> str:  
    cipher = DES.new(key.ljust(8)[:8].encode('utf-8'), DES.MODE_ECB)  
    decrypted = cipher.decrypt(base64.b64decode(encrypted.encode('utf-8')))  
    padding_length = decrypted[-1]  
    return decrypted[:-padding_length].decode('utf-8')  

# AES-256 GCM encryption and decryption with PBKDF2 key derivation
def derive_key(password: str, salt: bytes, iterations: int = 100000) -> bytes:
    return PBKDF2(password, salt, dkLen=32, count=iterations)

def aes_gcm_encrypt(password: str, plaintext: str) -> dict:
    salt = get_random_bytes(16)  # Generate a random salt
    key = derive_key(password, salt)  # Derive a 256-bit key
    cipher = AES.new(key, AES.MODE_GCM)  # AES-256 in GCM mode
    nonce = cipher.nonce  # Random nonce
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))  # Encrypt and authenticate
    return {
        'salt': base64.b64encode(salt).decode('utf-8'),
        'nonce': base64.b64encode(nonce).decode('utf-8'),
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
        'tag': base64.b64encode(tag).decode('utf-8')
    }

def aes_gcm_decrypt(password: str, encrypted_data: dict) -> str:
    salt = base64.b64decode(encrypted_data['salt'])
    nonce = base64.b64decode(encrypted_data['nonce'])
    ciphertext = base64.b64decode(encrypted_data['ciphertext'])
    tag = base64.b64decode(encrypted_data['tag'])
    key = derive_key(password, salt)  # Derive the same 256-bit key
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)  # AES-256 in GCM mode
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)  # Decrypt and verify
    return plaintext.decode('utf-8')

@app.route('/')  
def home():  
    return render_template('index.html', otpResult='', desResult='', aesResult='')  

@app.route('/encrypt', methods=['POST'])  
def encrypt():  
    data = request.json  
    method = data['method']  
    key = data['key']  
    message = data['message']  
    
    result = ''
    if method == 'otp':  
        result = otp_encrypt(message, key)  
    elif method == 'des':  
        result = des_encrypt(key, message)  
    elif method == 'aes':  
        result = aes_gcm_encrypt(key, message)  
    else:  
        return jsonify({'error': 'Invalid method'}), 400  
    
    return render_template('index.html', otpResult=(result if method == 'otp' else ''), 
                           desResult=(result if method == 'des' else ''), 
                           aesResult=(result if method == 'aes' else ''))  

@app.route('/decrypt', methods=['POST'])  
def decrypt():  
    data = request.json  
    method = data['method']  
    key = data['key']  
    encrypted_message = data['message']  
    
    result = ''
    if method == 'otp':  
        result = otp_decrypt(encrypted_message, key)  
    elif method == 'des':  
        result = des_decrypt(key, encrypted_message)  
    elif method == 'aes':  
        result = aes_gcm_decrypt(key, encrypted_message)  
    else:  
        return jsonify({'error': 'Invalid method'}), 400  
    
    return render_template('index.html', otpResult=(result if method == 'otp' else ''), 
                           desResult=(result if method == 'des' else ''), 
                           aesResult=(result if method == 'aes' else ''))  

@app.route('/api/aes/encrypt', methods=['POST'])  
def api_encrypt_aes():  
    data = request.json  
    password = data['password']  
    plaintext = data['plaintext']  
    result = aes_gcm_encrypt(password, plaintext)  
    return jsonify(result)  

@app.route('/api/3des/encrypt', methods=['POST'])  
def api_encrypt_3des():  
    data = request.json  
    key = data['key']  
    plaintext = data['plaintext']  
    result = des_encrypt(key, plaintext)  
    return jsonify({'encrypted_text': result})  

@app.route('/api/otp/encrypt', methods=['POST'])  
def api_encrypt_otp():  
    data = request.json  
    plaintext = data['plaintext']  
    key = data['key']
    try:
        result = otp_encrypt(plaintext, key)  
        return jsonify({'encrypted_text': result})  
    except ValueError as e:
        return jsonify({'error': str(e)}), 400  

@app.route('/api/aes/decrypt', methods=['POST'])
def api_decrypt_aes():
    data = request.json
    password = data['password']
    encrypted_data = {
        'salt': data['salt'],
        'nonce': data['nonce'],
        'ciphertext': data['ciphertext'],
        'tag': data['tag']
    }
    try:
        plaintext = aes_gcm_decrypt(password, encrypted_data)
        return jsonify({'decrypted_text': plaintext})
    except (ValueError, KeyError) as e:
        return jsonify({'error': 'Decryption failed: ' + str(e)}), 400

@app.route('/api/3des/decrypt', methods=['POST'])
def api_decrypt_3des():
    data = request.json
    key = data['key']
    encrypted = data['encrypted']
    result = des_decrypt(key, encrypted)
    return jsonify({'decrypted_text': result})

@app.route('/api/otp/decrypt', methods=['POST'])
def api_decrypt_otp():
    data = request.json
    encrypted = data['encrypted']
    key = data['key']
    if len(key) < len(encrypted):
        return jsonify({'error': 'Key must be at least as long as the encrypted message.'}), 400
    try:
        result = otp_decrypt(encrypted, key)
        return jsonify({'decrypted_text': result})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':  
    app.run()
