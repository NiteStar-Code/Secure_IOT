// ================================================================
//  ESP32 SecurePack — XTEA-CBC + ESP-Now Receiver
//  Generated: {{DATE}}
//  Key: {{KEY_HEX}}
// ================================================================
#include <esp_now.h>
#include <WiFi.h>

// --- Auto-Generated XTEA Key (16 bytes) ---
const uint8_t xtea_key[16] = {{KEY_C}};

#define MAX_PT 232
typedef struct { 
    uint8_t iv[8]; 
    uint8_t len; 
    uint8_t ct[MAX_PT]; 
} XPacket;

void xtea_dec(uint8_t v[8], const uint8_t k[16]) {
  uint32_t v0=((uint32_t)v[0]<<24)|((uint32_t)v[1]<<16)|((uint32_t)v[2]<<8)|v[3];
  uint32_t v1=((uint32_t)v[4]<<24)|((uint32_t)v[5]<<16)|((uint32_t)v[6]<<8)|v[7];
  uint32_t key[4];
  for(int i=0;i<4;i++) key[i]=((uint32_t)k[i*4]<<24)|((uint32_t)k[i*4+1]<<16)|((uint32_t)k[i*4+2]<<8)|k[i*4+3];
  uint32_t delta=0x9E3779B9,sum=delta*32;
  
  for(int i=0;i<32;i++){
      v1-=(((v0<<4)^(v0>>5))+v0)^(sum+key[(sum>>11)&3]);
      sum-=delta;
      v0-=(((v1<<4)^(v1>>5))+v1)^(sum+key[sum&3]);
  }
  
  v[0]=(v0>>24)&0xFF; v[1]=(v0>>16)&0xFF; v[2]=(v0>>8)&0xFF; v[3]=v0&0xFF;
  v[4]=(v1>>24)&0xFF; v[5]=(v1>>16)&0xFF; v[6]=(v1>>8)&0xFF; v[7]=v1&0xFF;
}

void onReceive(const uint8_t* mac, const uint8_t* data, int len) {
  if(len < 9) { Serial.println("[RX] Short packet"); return; }
  
  const XPacket* pkt = (const XPacket*)data;
  uint8_t fb[8]; 
  memcpy(fb, pkt->iv, 8);
  char plain[MAX_PT+1] = {0};
  
  for(size_t i=0; i<pkt->len; i+=8){
    uint8_t blk[8]; 
    memcpy(blk, pkt->ct+i, 8);
    
    uint8_t tmp[8]; 
    memcpy(tmp, blk, 8);
    xtea_dec(tmp, xtea_key);
    
    for(int b=0; b<8 && (i+b)<pkt->len; b++) plain[i+b] = tmp[b]^fb[b];
    memcpy(fb, blk, 8);
  }
  
  Serial.print("[RX] Decrypted: "); 
  Serial.println(plain);
}

void setup() {
  Serial.begin(115200); 
  WiFi.mode(WIFI_STA);
  
  if(esp_now_init() != ESP_OK){
      Serial.println("ESP-Now initialization failed");
      return;
  }
  
  esp_now_register_recv_cb(esp_now_recv_cb_t(onReceive));
  
  Serial.println("XTEA ESP-Now Receiver ready");
  Serial.println("Device MAC Address: " + WiFi.macAddress());
}

void loop() {
    // Waiting for ESP-Now callbacks
}
