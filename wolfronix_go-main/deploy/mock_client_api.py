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

print(f"🚀 Mock Client API running on port 4000")
print(f"📂 Storage directory: {os.path.abspath(STORAGE_DIR)}")

# Auto-increment file ID — uses a file-based counter so it survives:
# 1. Container restarts (persisted to disk)
# 2. Gunicorn multi-worker (file lock ensures atomic increment)
COUNTER_FILE = os.path.join(STORAGE_DIR, "counter.txt")
import fcntl

def _init_counter():
    """Initialize the counter file from existing files if it doesn't exist."""
    if os.path.exists(COUNTER_FILE):
        return
    # Scan existing files to find highest ID
    max_id = 0
    if os.path.exists(FILES_DIR):
        for filename in os.listdir(FILES_DIR):
            base = filename.replace('dev_', '').split('.')[0]
            try:
                fid = int(base)
                if fid > max_id:
                    max_id = fid
            except (ValueError, IndexError):
                continue
    with open(COUNTER_FILE, 'w') as f:
        f.write(str(max_id + 1))
    print(f"📊 Initialized counter file at {max_id + 1}")

_init_counter()

def _gen_file_id():
    """Atomically read-and-increment the file-based counter (safe across workers)."""
    with open(COUNTER_FILE, 'r+') as f:
        fcntl.flock(f, fcntl.LOCK_EX)  # Exclusive lock
        current = int(f.read().strip())
        f.seek(0)
        f.write(str(current + 1))
        f.truncate()
        fcntl.flock(f, fcntl.LOCK_UN)
    return current

@app.route('/wolfronix/files/upload', methods=['POST'])
def upload_file():
    print(f"📥 Received file upload request")
    
    # Metadata is sent as a JSON string in 'metadata' field
    metadata_json = request.form.get('metadata')
    if not metadata_json:
        return jsonify({"error": "Missing metadata"}), 400
    
    file_meta = json.loads(metadata_json)
    file_id = _gen_file_id()
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
        
    print(f"✅ Stored file {file_id}: {file_meta.get('filename', 'unknown')}")
    return jsonify({"id": file_id}), 201

@app.route('/wolfronix/files', methods=['POST'])
def store_file_metadata():
    """Store file metadata only (JSON body, no multipart upload)."""
    data = request.json
    if not data:
        return jsonify({"error": "Missing JSON body"}), 400

    file_id = _gen_file_id()
    data['id'] = file_id

    meta_path = os.path.join(FILES_DIR, f"{file_id}.json")
    with open(meta_path, 'w') as f:
        json.dump(data, f)

    print(f"📝 Stored metadata {file_id}: {data.get('filename', 'unknown')}")
    return jsonify({"id": file_id}), 201

@app.route('/wolfronix/files/<int:file_id>', methods=['GET'])
def get_file_meta(file_id):
    meta_path = os.path.join(FILES_DIR, f"{file_id}.json")
    if not os.path.exists(meta_path):
        return jsonify({"error": "File not found"}), 404
        
    with open(meta_path, 'r') as f:
        meta = json.load(f)
        
    return jsonify(meta)

@app.route('/wolfronix/files/<int:file_id>/data', methods=['GET'])
def get_file_data(file_id):
    file_path = os.path.join(FILES_DIR, f"{file_id}.enc")
    if not os.path.exists(file_path):
        return jsonify({"error": "File data not found"}), 404
        
    return send_file(file_path, mimetype='application/octet-stream')

@app.route('/wolfronix/files', methods=['GET'])
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

@app.route('/wolfronix/keys', methods=['POST'])
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

@app.route('/wolfronix/keys/<user_id>', methods=['GET'])
def get_key(user_id):
    key_path = os.path.join(KEYS_DIR, f"{user_id}.json")
    if not os.path.exists(key_path):
        return jsonify({"error": "Key not found"}), 404
        
    with open(key_path, 'r') as f:
        data = json.load(f)
        
    return jsonify(data)

@app.route('/wolfronix/keys/<user_id>/public', methods=['GET'])
def get_public_key(user_id):
    key_path = os.path.join(KEYS_DIR, f"{user_id}.json")
    if not os.path.exists(key_path):
        return jsonify({"error": "Key not found"}), 404
        
    with open(key_path, 'r') as f:
        data = json.load(f)
        
    return jsonify({"public_key_pem": data.get('public_key_pem')})

@app.route('/wolfronix/files/<int:file_id>', methods=['DELETE'])
def delete_file(file_id):
    """Delete a file and its metadata."""
    meta_path = os.path.join(FILES_DIR, f"{file_id}.json")
    data_path = os.path.join(FILES_DIR, f"{file_id}.enc")
    
    if not os.path.exists(meta_path):
        return jsonify({"error": "File not found"}), 404
    
    os.remove(meta_path)
    if os.path.exists(data_path):
        os.remove(data_path)
    
    print(f"🗑️  Deleted file {file_id}")
    return jsonify({"status": "deleted", "id": file_id}), 200

@app.route('/wolfronix/dev/files', methods=['POST'])
def store_dev_files():
    """Store fake/development data (Layer 1 fake-gen output)."""
    data = request.json
    if not data:
        return jsonify({"error": "Missing JSON body"}), 400

    file_id = _gen_file_id()
    data['id'] = file_id
    data['dev'] = True

    meta_path = os.path.join(FILES_DIR, f"dev_{file_id}.json")
    with open(meta_path, 'w') as f:
        json.dump(data, f)

    print(f"🧪 Stored dev data {file_id}")
    return jsonify({"id": file_id}), 201

if __name__ == '__main__':
    # Listen on all interfaces
    app.run(host='0.0.0.0', port=4000)
