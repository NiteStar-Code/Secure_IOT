#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <time.h>

// --- Network Configuration ---
const char* ssid = {{SSID}};
const char* password = {{PASS}};
const char* server_url = "https://{{IP}}/api/endpoint"; 

// --- Security Configuration ---
const uint8_t xtea_key[16] = {{KEY_C}};

// Provide the Root CA for HTTPS validation. 
// If you are testing locally without a valid certificate, you can skip this 
// and use espClient.setInsecure() in setup().
const char* root_ca = \
"-----BEGIN CERTIFICATE-----\n" \
"PASTE_YOUR_CA_CRT_HERE\n" \
"-----END CERTIFICATE-----";

// --- Global Objects ---
WiFiClientSecure espClient;

// --- 1. XTEA Encryption Core ---
void xtea_block_encrypt(unsigned int num_rounds, uint8_t v[8], const uint8_t k[16]) {
    uint32_t v0 = ((uint32_t)v[0] << 24) | ((uint32_t)v[1] << 16) | ((uint32_t)v[2] << 8) | v[3];
    uint32_t v1 = ((uint32_t)v[4] << 24) | ((uint32_t)v[5] << 16) | ((uint32_t)v[6] << 8) | v[7];
    
    uint32_t key[4];
    for (int i = 0; i < 4; i++) {
        key[i] = ((uint32_t)k[i*4] << 24) | ((uint32_t)k[i*4+1] << 16) | ((uint32_t)k[i*4+2] << 8) | k[i*4+3];
    }

    uint32_t sum = 0, delta = 0x9E3779B9;
    for (unsigned int i = 0; i < num_rounds; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
    }

    v[0] = (v0 >> 24) & 0xFF; v[1] = (v0 >> 16) & 0xFF; v[2] = (v0 >> 8) & 0xFF; v[3] = v0 & 0xFF;
    v[4] = (v1 >> 24) & 0xFF; v[5] = (v1 >> 16) & 0xFF; v[6] = (v1 >> 8) & 0xFF; v[7] = v1 & 0xFF;
}

// Core function: Encrypts a String and returns Hex
String encryptXtea(String plaintext, const uint8_t key[16]) {
    size_t orig_len = plaintext.length();
    size_t padded_len = ((orig_len + 7) / 8) * 8;
    
    uint8_t* padded_buffer = new uint8_t[padded_len];
    memset(padded_buffer, 0, padded_len);
    memcpy(padded_buffer, plaintext.c_str(), orig_len);

    uint8_t feedback[8];
    String hexOutput = "";
    char hexTemp[3];

    for(int i = 0; i < 8; i++) {
        feedback[i] = (uint8_t)esp_random();
        sprintf(hexTemp, "%02X", feedback[i]);
        hexOutput += hexTemp;
    }

    for (size_t i = 0; i < padded_len; i += 8) {
        uint8_t current_block[8];
        memcpy(current_block, padded_buffer + i, 8);

        for (int b = 0; b < 8; b++) {
            current_block[b] ^= feedback[b];
        }

        xtea_block_encrypt(32, current_block, key);

        for (int b = 0; b < 8; b++) {
            sprintf(hexTemp, "%02X", current_block[b]);
            hexOutput += hexTemp;
            feedback[b] = current_block[b];
        }
    }
    
    delete[] padded_buffer;
    return hexOutput;
}

// Overloaded function: Converts int to String and encrypts
String encryptXtea(int value, const uint8_t key[16]) {
    return encryptXtea(String(value), key);
}

// --- 2. HTTPS POST Function ---
void sendHTTPS(String encryptedPayload) {
    Serial.print("Sending Encrypted Payload: ");
    Serial.println(encryptedPayload);
    
    HTTPClient http;
    http.begin(espClient, server_url); 
    
    // Adjust Content-Type if your server expects JSON ("application/json")
    http.addHeader("Content-Type", "text/plain"); 

    int httpResponseCode = http.POST(encryptedPayload);

    if (httpResponseCode > 0) {
      Serial.print("HTTPS Response Code: ");
      Serial.println(httpResponseCode);
      String response = http.getString();
      Serial.println("Server Response: " + response);
    } else {
      Serial.print("HTTPS Error code: ");
      Serial.println(httpResponseCode);
      Serial.println(http.errorToString(httpResponseCode).c_str());
    }

    http.end();
}

// --- 3. NTP Time Sync (Vital for HTTPS) ---
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

void setup() {
  Serial.begin(115200);
  WiFi.begin(ssid, password);
  
  Serial.print("Connecting to WiFi");
  while (WiFi.status() != WL_CONNECTED) { 
    delay(500); 
    Serial.print("."); 
  }
  Serial.println("\nWiFi Connected");
  
  setClock(); 
  espClient.setCACert(root_ca); 
  

}

void loop() {
  if (WiFi.status() == WL_CONNECTED) {
    // 1. Generate data
    int randomVal = random(0, 1000);
    
    // 2. Encrypt using XTEA
    String encryptedData = encryptXtea(randomVal, xtea_key);
    
    // 3. Send via HTTPS
    sendHTTPS(encryptedData);
  } else {
    Serial.println("WiFi Disconnected. Waiting...");
  }

  delay(5000);
}