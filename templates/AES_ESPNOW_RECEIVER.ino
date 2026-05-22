#include <esp_now.h>
#include <WiFi.h>
#include <mbedtls/gcm.h>
#include <mbedtls/base64.h> // Used for safe binary base64 decoding

// --- Security Configuration ---
// FIXED: Changed from 'const char*' to a byte array 'const uint8_t aes_key[]'
const uint8_t aes_key[] = {
    0xB4, 0xCC, 0x13, 0xDF, 0x27, 0x00, 0xCB, 0x04,
    0xAA, 0xFF, 0x13, 0xC1, 0xBE, 0x7F, 0xB8, 0xF1,
    0x68, 0xB5, 0xA9, 0x0E, 0xA4, 0xEF, 0x11, 0x30,
    0x96, 0xEF, 0xEF, 0x6F, 0xBB, 0x13, 0x3C, 0xEB
}; 

// --- Decryption Function ---
String decryptData(String payload) {
    // 1. Split the string by the ':' delimiter
    int firstColon = payload.indexOf(':');
    int secondColon = payload.indexOf(':', firstColon + 1);
    
    if (firstColon == -1 || secondColon == -1) {
        return "Error: Invalid Payload Format";
    }

    String iv64 = payload.substring(0, firstColon);
    String tag64 = payload.substring(firstColon + 1, secondColon);
    String ct64 = payload.substring(secondColon + 1);

    // 2. Decode the Base64 strings back to binary arrays
    unsigned char iv[12];
    size_t iv_len;
    mbedtls_base64_decode(iv, sizeof(iv), &iv_len, (const unsigned char*)iv64.c_str(), iv64.length());

    unsigned char tag[16];
    size_t tag_len;
    mbedtls_base64_decode(tag, sizeof(tag), &tag_len, (const unsigned char*)tag64.c_str(), tag64.length());

    // Dynamically allocate ciphertext buffer based on base64 length
    size_t max_ct_len = ct64.length();
    unsigned char* ciphertext = new unsigned char[max_ct_len];
    size_t ct_len;
    mbedtls_base64_decode(ciphertext, max_ct_len, &ct_len, (const unsigned char*)ct64.c_str(), ct64.length());

    // 3. Decrypt and Verify the Tag
    unsigned char* plaintext = new unsigned char[ct_len + 1]; // +1 for null terminator
    
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, (const unsigned char*)aes_key, 256);
    
    // mbedtls_gcm_auth_decrypt returns 0 on success, or an error code if the tag fails
    int ret = mbedtls_gcm_auth_decrypt(&gcm, ct_len, iv, 12, NULL, 0, tag, 16, ciphertext, plaintext);
    mbedtls_gcm_free(&gcm);

    String result = "";
    if (ret == 0) {
        plaintext[ct_len] = '\0'; // Properly terminate the string
        result = String((char*)plaintext);
    } else {
        result = "Decryption Failed! (Authentication Tag Mismatch)";
    }

    // 4. Free up memory
    delete[] ciphertext;
    delete[] plaintext;

    return result;
}

// --- ESP-NOW Receive Callback ---
void OnDataRecv(const uint8_t * mac, const uint8_t *incomingData, int len) {
    // 1. ESP-NOW data is not null-terminated natively, so we format it safely
    char* buf = new char[len + 1];
    memcpy(buf, incomingData, len);
    buf[len] = '\0'; 
    String encryptedPayload = String(buf);
    delete[] buf; // Free memory

    Serial.println("=============================");
    Serial.println("Received Encrypted: " + encryptedPayload);
    
    // 2. Decrypt the message
    String decryptedText = decryptData(encryptedPayload);
    
    // 3. Output the result
    Serial.println("Decrypted Value: " + decryptedText);
    Serial.println("=============================\n");
}

void setup() {
  Serial.begin(115200);
  
  // ESP-NOW requires Station Mode
  WiFi.mode(WIFI_STA);
  Serial.println();
  Serial.println("Device MAC Address: " + WiFi.macAddress());

  // Initialize ESP-NOW
  if (esp_now_init() != ESP_OK) {
    Serial.println("Error initializing ESP-NOW");
    return;
  }

  // Register the receive callback
  esp_now_register_recv_cb(esp_now_recv_cb_t(OnDataRecv));
  
  Serial.println("Receiver Ready. Waiting for encrypted data...");
}

void loop() {
  // ESP-NOW uses interrupts, so loop can stay empty or handle other tasks
  delay(1000);
}