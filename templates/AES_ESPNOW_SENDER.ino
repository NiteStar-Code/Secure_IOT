//Sends random encrypted integers via ESPNow

#include <esp_now.h>
#include <WiFi.h>
#include "mbedtls/gcm.h" // Required for AES-GCM encryption
#include <base64.h>      // Required for base64::encode

uint8_t broadcastAddress[] = {0x4C, 0X11, 0XAE, 0X70, 0X1C, 0XD8};

// FIXED: Changed from 'const char*' to a byte array 'const uint8_t aes_key[]'
const uint8_t aes_key[] = {
    0xB4, 0xCC, 0x13, 0xDF, 0x27, 0x00, 0xCB, 0x04,
    0xAA, 0xFF, 0x13, 0xC1, 0xBE, 0x7F, 0xB8, 0xF1,
    0x68, 0xB5, 0xA9, 0x0E, 0xA4, 0xEF, 0x11, 0x30,
    0x96, 0xEF, 0xEF, 0x6F, 0xBB, 0x13, 0x3C, 0xEB
}; // 32-byte key


void setClock() {
  configTime(0, 0, "pool.ntp.org", "time.google.com");
  Serial.print("Waiting for NTP time sync: ");
  time_t now = time(nullptr);
  while (now < 8 * 3600 * 2) {
    delay(500);
    Serial.print(".");
    now = time(nullptr);
  }
  Serial.println("\nTime synced!");
}


String encryptData(String data) {
    size_t input_len = data.length();
    if (input_len == 0) return ""; // Handle empty strings safely

    unsigned char iv[12];
    for(int i = 0; i < 12; i++) iv[i] = (unsigned char)random(0, 255); 

    // Dynamically allocate ciphertext array based on input length
    unsigned char* ciphertext = new unsigned char[input_len];
    unsigned char tag[16];

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    
    // The cast to (const unsigned char*) works perfectly now that aes_key is an array
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, (const unsigned char*)aes_key, 256);
    
    mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, input_len, iv, 12, NULL, 0, 
                              (const unsigned char*)data.c_str(), ciphertext, 16, tag);

    // Format: IV:TAG:CIPHERTEXT
    String output = base64::encode(iv, 12) + ":" + 
                    base64::encode(tag, 16) + ":" + 
                    base64::encode(ciphertext, input_len);

    mbedtls_gcm_free(&gcm);
    delete[] ciphertext; // Free the dynamically allocated memory
    
    return output;
}


String encryptData(int value) {
    return encryptData(String(value));
}

void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_STA); // Must be in Station mode for ESP-NOW

  if (esp_now_init() != ESP_OK) {
    Serial.println("Error initializing ESP-NOW");
    return;
  }

  // Register the Receiver as a "Peer"
  esp_now_peer_info_t peerInfo = {};
  memcpy(peerInfo.peer_addr, broadcastAddress, 6);
  peerInfo.channel = 0;  
  peerInfo.encrypt = false;
  
  if (esp_now_add_peer(&peerInfo) != ESP_OK){
    Serial.println("Failed to add peer");
    return;
  }
}

void loop() {
  int randomValue = random(1, 100); // Generate our random data
  
  // 1. Encrypt the data using the function we created earlier
  String encryptedPayload = encryptData(randomValue);
  
  // 2. Send the encrypted string to the Receiver
  esp_err_t result = esp_now_send(
    broadcastAddress, 
    (const uint8_t *)encryptedPayload.c_str(), 
    encryptedPayload.length()
  );
   
  if (result == ESP_OK) {
    Serial.println("Successfully Sent: " + encryptedPayload);
  } else {
    Serial.println("Error sending the data");
  }

  delay(2000); // Wait 2 seconds before sending the next one
}