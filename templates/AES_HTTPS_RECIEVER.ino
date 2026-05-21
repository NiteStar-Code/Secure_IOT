#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h> 
#include <mbedtls/gcm.h>
#include <base64.h>
#include <time.h>

const char* ssid = {{SSID}};
const char* password = {{PASS}};
const char* server_url = "https://{{IP}}/api/endpoint"; 

// --- Security Configuration ---
const char* aes_key = {{KEY_C}}; // 32-byte key
const char* root_ca = {{CA_C}};

// --- Global Objects ---
WiFiClientSecure espClient;

// --- 1. NTP Time Sync (Vital for HTTPS Certificates) ---
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

// --- 2. Encryption Functions ---

// Core function: Encrypts a String of any length
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

// Overloaded function: Converts int to String and encrypts
String encryptData(int value) {
    return encryptData(String(value));
}

// --- 3. HTTPS POST Function ---
void sendHTTPS(String encryptedPayload) {
    Serial.print("Sending Encrypted Payload: ");
    Serial.println(encryptedPayload);
    
    HTTPClient http;
    http.begin(espClient, server_url); // Pass the secure client and URL
    
    // Set content type. Adjust to "application/json" if sending a JSON string.
    http.addHeader("Content-Type", "text/plain"); 

    int httpResponseCode = http.POST(encryptedPayload); // Make the POST request

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

    http.end(); // Free HTTP resources
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
  
  setClock(); // Sync time for SSL validation
  espClient.setCACert(root_ca); // Provide the Root CA for HTTPS
}

void loop() {
  // Only try to send if we are connected to Wi-Fi
  if (WiFi.status() == WL_CONNECTED) {
    
    // 1. Generate data
    int randomVal = random(0, 1000);
    
    // 2. Encrypt the data
    String encryptedPayload = encryptData(randomVal);
    
    // 3. Send via HTTPS
    sendHTTPS(encryptedPayload);
    
  } else {
    Serial.println("WiFi Disconnected. Waiting...");
  }

  delay(5000);
}