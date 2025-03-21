from flask import Flask, request, jsonify, render_template  
from Crypto.Cipher import DES, AES  
import base64  

app = Flask(__name__)  

# One-time pad encryption  
def otp_encrypt(message, key):  
    if len(key) < len(message):
        raise ValueError("Key must be at least as long as the message.")  # Actively raise ValueError
    return ''.join(chr(ord(m) ^ ord(k)) for m, k in zip(message, key))  

def otp_decrypt(encrypted_message, key):  
    return otp_encrypt(encrypted_message, key)  # OTP is symmetric  

# DES encryption and decryption  
def des_encrypt(key, plaintext):  
    cipher = DES.new(key.ljust(8)[:8].encode('utf-8'), DES.MODE_ECB)  
    padded_text = plaintext + (8 - len(plaintext) % 8) * chr(8 - len(plaintext) % 8)  
    return base64.b64encode(cipher.encrypt(padded_text.encode('utf-8'))).decode('utf-8')  

def des_decrypt(key, encrypted):  
    cipher = DES.new(key.ljust(8)[:8].encode('utf-8'), DES.MODE_ECB)  
    decrypted = cipher.decrypt(base64.b64decode(encrypted.encode('utf-8')))  
    padding_length = decrypted[-1]  
    return decrypted[:-padding_length].decode('utf-8')  

# AES encryption and decryption  
def aes_encrypt(key, plaintext):  
    cipher = AES.new(key.ljust(16)[:16].encode('utf-8'), AES.MODE_ECB)  
    padded_text = plaintext + (16 - len(plaintext) % 16) * chr(16 - len(plaintext) % 16)  
    return base64.b64encode(cipher.encrypt(padded_text.encode('utf-8'))).decode('utf-8')  

def aes_decrypt(key, encrypted):  
    cipher = AES.new(key.ljust(16)[:16].encode('utf-8'), AES.MODE_ECB)  
    decrypted = cipher.decrypt(base64.b64decode(encrypted.encode('utf-8')))  
    padding_length = decrypted[-1]  
    return decrypted[:-padding_length].decode('utf-8')  

@app.route('/')  
def home():  
    return render_template('index.html', otpResult='', desResult='', aesResult='')  # Initialize variables  

@app.route('/encrypt', methods=['POST'])  
def encrypt():  
    data = request.json  
    method = data['method']  
    key = data['key']  
    message = data['message']  
    
    if method == 'otp':  
        result = otp_encrypt(message, key)  
        return render_template('index.html', otpResult=result, desResult='', aesResult='')  
    elif method == 'des':  
        result = des_encrypt(key, message)  
        return render_template('index.html', otpResult='', desResult=result, aesResult='')  
    elif method == 'aes':  
        result = aes_encrypt(key, message)  
        return render_template('index.html', otpResult='', desResult='', aesResult=result)  
    else:  
        return jsonify({'error': 'Invalid method'}), 400  

@app.route('/decrypt', methods=['POST'])  
def decrypt():  
    data = request.json  
    method = data['method']  
    key = data['key']  
    encrypted_message = data['message']  
    
    if method == 'otp':  
        result = otp_decrypt(encrypted_message, key)  
        return render_template('index.html', otpResult=result, desResult='', aesResult='')  
    elif method == 'des':  
        result = des_decrypt(key, encrypted_message)  
        return render_template('index.html', otpResult='', desResult=result, aesResult='')  
    elif method == 'aes':  
        result = aes_decrypt(key, encrypted_message)  
        return render_template('index.html', otpResult='', desResult='', aesResult=result)  
    else:  
        return jsonify({'error': 'Invalid method'}), 400  

@app.route('/api/aes/encrypt', methods=['POST'])  
def api_encrypt_aes():  
    data = request.json  
    key = data['key']  
    plaintext = data['plaintext']  
    result = aes_encrypt(key, plaintext)  
    return jsonify({'encrypted_text': result})  

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
        return jsonify({'error': str(e)}), 400  # Return error message in JSON response

@app.route('/api/aes/decrypt', methods=['POST'])
def api_decrypt_aes():
    data = request.json
    key = data['key']
    encrypted = data['encrypted']
    result = aes_decrypt(key, encrypted)
    return jsonify({'decrypted_text': result})

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