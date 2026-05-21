#include <esp_now.h>
#include <WiFi.h>

// Your Receiver's MAC Address
uint8_t broadcastAddress[] = {{MAC_C}};

const uint8_t xtea_key[16] = {{KEY_C}};

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

// --- New Encryption Functions ---

// Core function: Encrypts a String and returns Hex
String encryptXtea(String plaintext, const uint8_t key[16]) {
    size_t orig_len = plaintext.length();
    size_t padded_len = ((orig_len + 7) / 8) * 8;
    
    // Dynamically allocate to handle strings of any size
    uint8_t* padded_buffer = new uint8_t[padded_len];
    memset(padded_buffer, 0, padded_len);
    memcpy(padded_buffer, plaintext.c_str(), orig_len);

    uint8_t feedback[8];
    String hexOutput = "";
    char hexTemp[3];

    // 1. Generate IV (feedback block) and append to output as Hex
    for(int i = 0; i < 8; i++) {
        feedback[i] = (uint8_t)esp_random();
        sprintf(hexTemp, "%02X", feedback[i]);
        hexOutput += hexTemp;
    }

    // 2. Encrypt blocks using CBC mode and append to output as Hex
    for (size_t i = 0; i < padded_len; i += 8) {
        uint8_t current_block[8];
        memcpy(current_block, padded_buffer + i, 8);

        // XOR with previous block (CBC mode)
        for (int b = 0; b < 8; b++) {
            current_block[b] ^= feedback[b];
        }

        // Encrypt the block
        xtea_block_encrypt(32, current_block, key);

        // Append to Hex string and save for next block's XOR
        for (int b = 0; b < 8; b++) {
            sprintf(hexTemp, "%02X", current_block[b]);
            hexOutput += hexTemp;
            feedback[b] = current_block[b];
        }
    }
    
    delete[] padded_buffer; // Prevent memory leaks
    return hexOutput;
}

// Overloaded function: Converts int to String and encrypts
String encryptXtea(int value, const uint8_t key[16]) {
    return encryptXtea(String(value), key);
}



void setup() {
    Serial.begin(115200);
    delay(2000);

    // 1. Test String Encryption
    String long_msg = "He who must not be named 10001";
    String encryptedString = encryptXtea(long_msg, xtea_key);
    
    Serial.println("--- XTEA String Test ---");
    Serial.println("Plaintext: " + long_msg);
    Serial.println("Encrypted (Hex): " + encryptedString);
    Serial.println();

    // 2. Test Integer Encryption (Useful for ESP-NOW)
    int randomValue = 42;
    String encryptedInt = encryptXtea(randomValue, xtea_key);
    
    Serial.println("--- XTEA Integer Test ---");
    Serial.println("Plaintext: " + String(randomValue));
    Serial.println("Encrypted (Hex): " + encryptedInt);
}

void loop() {
    // You can put your esp_now_send logic here
    // esp_now_send(broadcastAddress, (const uint8_t *)encryptedString.c_str(), encryptedString.length());
}

