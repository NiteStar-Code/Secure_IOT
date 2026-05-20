// ================================================================
//  ESP32 SecurePack — AES-256-GCM + MQTTS Publisher
//  Generated: {{DATE}}
//  Key: {{KEY_HEX}}
// ================================================================
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <PubSubClient.h>
#include <mbedtls/gcm.h>
#include <base64.h>
#include <time.h>

// --- Network Configuration ---
const char* ssid        = "{{SSID}}";
const char* password    = "{{PASS}}";
const char* mqtt_server = "{{IP}}";
const int   mqtt_port   = 8883;

// --- Auto-Generated AES-256 Key (32 bytes) ---
const uint8_t aes_key[32] = {{KEY_C}};

// --- CA Certificate ---
const char* root_ca =
{{CA_C}}

WiFiClientSecure espClient;
PubSubClient client(espClient);

void setClock() {
  configTime(0, 0, "pool.ntp.org", "time.google.com");
  Serial.print("NTP sync");
  time_t now = time(nullptr);
  while (now < 8 * 3600 * 2) { delay(500); Serial.print("."); now = time(nullptr); }
  Serial.println(" OK");
}

void encryptAndPublish(const char* plaintext) {
  size_t len = strlen(plaintext);
  uint8_t iv[12], tag[16], ct[len];
  for (int i = 0; i < 12; i++) iv[i] = (uint8_t)esp_random();

  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, aes_key, 256);
  mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, len,
    iv, 12, NULL, 0, (const uint8_t*)plaintext, ct, 16, tag);
  mbedtls_gcm_free(&gcm);

  // Payload format: base64(IV):base64(TAG):base64(CT)
  String payload = base64::encode(iv, 12) + ":" +
                   base64::encode(tag, 16) + ":" +
                   base64::encode(ct, len);
                   
  Serial.println("[TX] " + payload);
  client.publish("esp32/secure/data", payload.c_str());
}

void reconnect() {
  while (!client.connected()) {
    Serial.print("MQTTS...");
    if (client.connect("ESP32_AES_Pub")) { Serial.println("OK"); }
    else { Serial.printf(" fail(%d) retry\n", client.state()); delay(5000); }
  }
}

void setup() {
  Serial.begin(115200);
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
  Serial.println("\nWiFi: " + WiFi.localIP().toString());
  
  setClock();
  espClient.setCACert(root_ca);
  client.setServer(mqtt_server, mqtt_port);
}

void loop() {
  if (!client.connected()) reconnect();
  client.loop();
  
  char msg[32]; 
  snprintf(msg, sizeof(msg), "val:%lu", millis());
  encryptAndPublish(msg);
  
  delay(5000);
}
