#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h> // Replaced PubSubClient with HTTPClient
#include <mbedtls/gcm.h>
#include <base64.h>
#include <time.h>

const char* ssid = {{SSID}};
const char* password = {{PASS}};
const char* server_url = "https://{{IP}}/api/endpoint"; 

// --- Security Configuration ---
const uint8_t aes_key[] = {{KEY_C}}; // 32-byte key
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

// --- 2. Encryption & HTTPS POST Function ---
void encryptAndSendHTTPS(int value) {
    char plaintext[16];
    sprintf(plaintext, "%d", value);
    size_t input_len = strlen(plaintext);

    unsigned char iv[12];
    for(int i=0; i<12; i++) iv[i] = (unsigned char)random(0, 255); 

    unsigned char ciphertext[16];
    unsigned char tag[16];

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, (const unsigned char*)aes_key, 256);
    
    mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, input_len, iv, 12, NULL, 0, 
                              (const unsigned char*)plaintext, ciphertext, 16, tag);


    String output = base64::encode(iv, 12) + ":" + 
                    base64::encode(tag, 16) + ":" + 
                    base64::encode(ciphertext, input_len);

    Serial.print("Sending Encrypted Payload: ");
    Serial.println(output);
    
    HTTPClient http;
    http.begin(espClient, server_url); // Pass the secure client and URL
    
    // Set content type. Adjust to "application/json" if sending a JSON string.
    http.addHeader("Content-Type", "text/plain"); 

    int httpResponseCode = http.POST(output); // Make the POST request

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
    mbedtls_gcm_free(&gcm); // Free encryption resources
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
    int randomVal = random(0, 1000);
    encryptAndSendHTTPS(randomVal);
  } else {
    Serial.println("WiFi Disconnected. Waiting...");
  }

  delay(5000);
}