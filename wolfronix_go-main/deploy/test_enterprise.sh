#!/bin/bash

# Configuration
SERVER_URL="https://49.206.202.13:9443"
CLIENT_ID="test_client_$(date +%s)"
USER_ID="test_user_$(date +%s)"
MOCK_API_URL="http://172.17.0.1:4000/api"  # Public IP for mock API
MOCK_API_KEY="test_key_123"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}=== Wolfronix Enterprise E2E Test ===${NC}"
echo "Client ID: $CLIENT_ID"
echo "User ID:   $USER_ID"
echo "Server:    $SERVER_URL"
echo ""

# 1. Register Client
echo -e "${GREEN}[1/5] Registering Enterprise Client...${NC}"
REG_RESP=$(curl -sk -X POST "$SERVER_URL/api/v1/enterprise/register" \
  -H "Content-Type: application/json" \
  -d "{
    \"client_id\": \"$CLIENT_ID\",
    \"client_name\": \"Test Client\",
    \"api_endpoint\": \"$MOCK_API_URL\",
    \"api_key\": \"$MOCK_API_KEY\"
  }")

if [[ $REG_RESP == *"success"* ]]; then
    echo "✅ Client Registered"
else
    echo -e "${RED}❌ Client Registration Failed: $REG_RESP${NC}"
    exit 1
fi

# 2. Generate User Keys (Locally)
echo -e "${GREEN}[2/5] Generating RSA Keys...${NC}"
openssl genrsa -out user_priv.pem 2048 2>/dev/null
openssl rsa -in user_priv.pem -pubout -out user_pub.pem 2>/dev/null

# Read key for JSON payload (single line with \n)
PUB_KEY_PEM=$(cat user_pub.pem | awk '{printf "%s\\n", $0}')

# Register User Keys (Mocking the wrapping process)
echo -e "${GREEN}[3/5] Registering User Keys...${NC}"
curl -sk -X POST "$SERVER_URL/api/v1/keys/register" \
  -H "Content-Type: application/json" \
  -d "{
    \"client_id\": \"$CLIENT_ID\",
    \"user_id\": \"$USER_ID\",
    \"public_key_pem\": \"$PUB_KEY_PEM\",
    \"encrypted_private_key\": \"dummy_wrapped_key\",
    \"salt\": \"dummy_salt\"
  }" > /dev/null
echo "✅ User Keys Registered"

# 3. Encrypt File
echo -e "${GREEN}[4/5] Encrypting File...${NC}"
echo "Top Secret Data $(date)" > secret.txt

ENC_RESP=$(curl -sk -X POST "$SERVER_URL/api/v1/encrypt" \
  -H "X-Client-ID: $CLIENT_ID" \
  -H "X-User-ID: $USER_ID" \
  -H "X-Environment: dev" \
  -F "file=@secret.txt" \
  -F "client_public_key=<user_pub.pem")

echo "Response: $ENC_RESP"

# Extract File ID
FILE_ID=$(echo $ENC_RESP | grep -o '"file_id":[0-9]*' | grep -o '[0-9]*')

if [[ -z "$FILE_ID" ]]; then
    echo -e "${RED}❌ Encryption Failed${NC}"
    exit 1
fi
echo "✅ File Encrypted (ID: $FILE_ID)"

# 4. Decrypt File
echo -e "${GREEN}[5/5] Decrypting File...${NC}"
curl -sk -X POST "$SERVER_URL/api/v1/files/$FILE_ID/decrypt" \
  -H "X-Client-ID: $CLIENT_ID" \
  -H "X-User-ID: $USER_ID" \
  -H "X-User-Role: owner" \
  -F "client_private_key=<user_priv.pem" > decrypted.txt

# Verify
ORIGINAL=$(cat secret.txt)
DECRYPTED=$(cat decrypted.txt)

echo ""
echo "Original:  $ORIGINAL"
echo "Decrypted: $DECRYPTED"
echo ""

if [[ "$ORIGINAL" == "$DECRYPTED" ]]; then
    echo -e "${GREEN}🎉 SUCCESS: Decrypted data matches original!${NC}"
    
    # Clean up
    rm user_priv.pem user_pub.pem secret.txt decrypted.txt
else
    echo -e "${RED}❌ FAILED: Data mismatch!${NC}"
    cat decrypted.txt
fi
