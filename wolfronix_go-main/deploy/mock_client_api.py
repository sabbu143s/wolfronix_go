import os
import json
import time
from flask import Flask, request, jsonify, send_file
import threading

app = Flask(__name__)

# Storage directories
STORAGE_DIR = "mock_storage"
FILES_DIR = os.path.join(STORAGE_DIR, "files")
KEYS_DIR = os.path.join(STORAGE_DIR, "keys")

os.makedirs(FILES_DIR, exist_ok=True)
os.makedirs(KEYS_DIR, exist_ok=True)

# In-memory metadata store (persisted to disk for simplicity would require DB)
# For this mock, we'll just use file system and some simple JSON files
file_metadata = {}

print(f"🚀 Mock Client API running on port 8080")
print(f"📂 Storage directory: {os.path.abspath(STORAGE_DIR)}")

@app.route('/api/wolfronix/files/upload', methods=['POST'])
def upload_file():
    print(f"📥 Received file upload request")
    
    # Metadata is sent as a JSON string in 'metadata' field
    metadata_json = request.form.get('metadata')
    if not metadata_json:
        return jsonify({"error": "Missing metadata"}), 400
    
    file_meta = json.loads(metadata_json)
    file_id = int(time.time() * 1000) # Simple ID generation
    file_meta['id'] = file_id
    
    # Encrypted data file
    if 'encrypted_data' not in request.files:
        return jsonify({"error": "Missing encrypted_data file"}), 400
        
    file = request.files['encrypted_data']
    file_path = os.path.join(FILES_DIR, f"{file_id}.enc")
    file.save(file_path)
    
    # Save metadata
    meta_path = os.path.join(FILES_DIR, f"{file_id}.json")
    with open(meta_path, 'w') as f:
        json.dump(file_meta, f)
        
    print(f"✅ Stored file {file_id}: {file_meta['filename']}")
    return jsonify({"id": file_id}), 201

@app.route('/api/wolfronix/files/<int:file_id>', methods=['GET'])
def get_file_meta(file_id):
    meta_path = os.path.join(FILES_DIR, f"{file_id}.json")
    if not os.path.exists(meta_path):
        return jsonify({"error": "File not found"}), 404
        
    with open(meta_path, 'r') as f:
        meta = json.load(f)
        
    return jsonify(meta)

@app.route('/api/wolfronix/files/<int:file_id>/data', methods=['GET'])
def get_file_data(file_id):
    file_path = os.path.join(FILES_DIR, f"{file_id}.enc")
    if not os.path.exists(file_path):
        return jsonify({"error": "File data not found"}), 404
        
    return send_file(file_path, mimetype='application/octet-stream')

@app.route('/api/wolfronix/files', methods=['GET'])
def list_files():
    user_id = request.args.get('user_id')
    files = []
    
    for filename in os.listdir(FILES_DIR):
        if filename.endswith(".json"):
            with open(os.path.join(FILES_DIR, filename), 'r') as f:
                try:
                    meta = json.load(f)
                    if user_id and meta.get('user_id') != user_id:
                        continue
                    files.append(meta)
                except:
                    continue
                    
    return jsonify(files)

@app.route('/api/wolfronix/keys', methods=['POST'])
def store_key():
    data = request.json
    user_id = data.get('user_id')
    if not user_id:
        return jsonify({"error": "Missing user_id"}), 400
        
    key_path = os.path.join(KEYS_DIR, f"{user_id}.json")
    with open(key_path, 'w') as f:
        json.dump(data, f)
        
    print(f"🔑 Stored keys for user {user_id}")
    return jsonify({"status": "success"}), 201

@app.route('/api/wolfronix/keys/<user_id>', methods=['GET'])
def get_key(user_id):
    key_path = os.path.join(KEYS_DIR, f"{user_id}.json")
    if not os.path.exists(key_path):
        return jsonify({"error": "Key not found"}), 404
        
    with open(key_path, 'r') as f:
        data = json.load(f)
        
    return jsonify(data)

@app.route('/api/wolfronix/keys/<user_id>/public', methods=['GET'])
def get_public_key(user_id):
    key_path = os.path.join(KEYS_DIR, f"{user_id}.json")
    if not os.path.exists(key_path):
        return jsonify({"error": "Key not found"}), 404
        
    with open(key_path, 'r') as f:
        data = json.load(f)
        
    return jsonify({"public_key_pem": data.get('public_key_pem')})

if __name__ == '__main__':
    # Listen on all interfaces
    app.run(host='0.0.0.0', port=4000)
