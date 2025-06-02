/**
 * @file EmotiBitSecurityHost.h
 * @brief Security module for handling encryption, decryption, signing and verification
 *        of messages exchanged with EmotiBit devices using PSK-based AES and HMAC.
 * @author Marina Rull Ventura
 * @date 01-07-2025
 */

#pragma once

#include <vector>
#include <string>
#include <map>
#include <array>
#include <mutex>
#include <iostream>
#include <mbedtls/aes.h>
#include <mbedtls/md.h>
#include <ofMain.h>

#define PSK_LENGTH 32
#define AES_BLOCK_SIZE 16
#define HMAC_LEN 32

class EmotiBitSecurityHost {
public:
    // ========== Common functions ==========

    /**
     * @brief Adds PKCS#7 padding to the message.
     * @param message The string to be padded (modified in-place).
     * @param blockSize The block size (typically 16 bytes for AES).
     * @return True if padding is applied correctly.
     */
    bool padMessage(std::string& message, uint8_t blockSize) const;

    /**
     * @brief Removes PKCS#7 padding from the decrypted message.
     * @param data Vector of decrypted bytes (modified in-place).
     * @param blockSize The block size used during encryption.
     * @return True if padding is valid and removed.
     */
    bool removePadding(std::vector<uint8_t>& data, uint8_t blockSize) const;

    /**
     * @brief Encrypts input data using AES-256 in ECB mode.
     * @param key AES-256 key (32 bytes).
     * @param input Pointer to the plaintext.
     * @param len Length of the plaintext.
     * @return Encrypted data.
     */
    std::vector<uint8_t> aesEncrypt(const uint8_t* key, const uint8_t* input, size_t len) const;

    /**
     * @brief Decrypts input data using AES-256 in ECB mode.
     * @param key AES-256 key (32 bytes).
     * @param input Pointer to the ciphertext.
     * @param len Length of the ciphertext.
     * @return Decrypted data.
     */
    std::vector<uint8_t> aesDecrypt(const uint8_t* key, const uint8_t* input, size_t len) const;

    /**
     * @brief Computes HMAC-SHA256 for input data.
     * @param key HMAC key (32 bytes).
     * @param data Input data pointer.
     * @param len Length of input data.
     * @return HMAC result (32 bytes).
     */
    std::vector<uint8_t> calculateHmac(const uint8_t* key, const uint8_t* data, size_t len) const;

    /**
     * @brief Splits input into ciphertext and HMAC components.
     * @param input Full input vector.
     * @param cipherOut Output vector for ciphertext.
     * @param hmacOut Output vector for HMAC.
     * @return True if split is successful.
     */
    bool splitCipherAndHmac(const std::vector<uint8_t>& input, std::vector<uint8_t>& cipherOut, std::vector<uint8_t>& hmacOut) const;

    /**
     * @brief Verifies message HMAC.
     * @param cipher Encrypted message.
     * @param hmac Provided HMAC.
     * @param key HMAC key.
     * @return True if HMAC is valid.
     */
    bool verifyOnly(const std::vector<uint8_t>& cipher, const std::vector<uint8_t>& hmac, const uint8_t* key) const;

    /**
     * @brief Decrypts a message without HMAC verification.
     * @param cipher Encrypted data.
     * @param plaintextOut Output plaintext string.
     * @param key AES key.
     * @return True if decryption succeeds.
     */
    bool decryptOnly(const std::vector<uint8_t>& cipher, std::string& plaintextOut, const uint8_t* key) const;

    /**
     * @brief Decrypts and verifies an encrypted message.
     * @param input Full message with ciphertext and HMAC.
     * @param plaintextOut Output plaintext string.
     * @param key AES/HMAC key.
     * @return True if both decryption and verification succeed.
     */
    bool decryptAndVerify(const std::vector<uint8_t>& input, std::string& plaintextOut, const uint8_t* key) const;

    /**
     * @brief Encrypts and signs a message using AES and HMAC.
     * @param message Plaintext to encrypt.
     * @param aesKey AES-256 key.
     * @param hmacKey HMAC-SHA256 key.
     * @param outEncrypted Output combined ciphertext + HMAC.
     * @return True if successful.
     */
    bool encryptAndSign(const std::string& message, const uint8_t* aesKey, const uint8_t* hmacKey, std::vector<uint8_t>& outEncrypted) const;

    // ========== Specific functions ==========

    /**
     * @brief Loads PSKs from remote JSON (URL).
     * @param url Endpoint providing device keys.
     * @return True if the Oscilloscope key is loaded.
     */
    bool loadKeysFromUrl(const std::string& url);

    /**
     * @brief Encrypts and signs a message with the Oscilloscope's PSK.
     * @param plaintext Plain message to secure.
     * @return Encrypted and signed message.
     */
    std::vector<uint8_t> encryptAndSignWithOscilloscope(const std::string& plaintext);

    /**
     * @brief Decrypts and verifies a packet from the connected EmotiBit.
     * @param encryptedPacket Full packet.
     * @param plaintextOut Decrypted output.
     * @return True if the operation is successful.
     */
    bool decryptAndVerifyFromConnected(const std::vector<uint8_t>& encryptedPacket, std::string& plaintextOut);

    /**
     * @brief Verifies a packet using the key of the connected EmotiBit.
     * @param cipher Encrypted portion.
     * @param hmac Provided HMAC.
     * @return True if valid.
     */
    bool verifyConnectedPacket(const std::vector<uint8_t>& cipher, const std::vector<uint8_t>& hmac) const;

    /**
     * @brief Decrypts advertisement packet from an EmotiBit.
     * @param encryptedPacket Packet to decrypt.
     * @param packetsOut Decrypted payloads.
     * @param cipherOut Extracted cipher.
     * @param hmacOut Extracted HMAC.
     * @return True if successful.
     */
    bool decryptAdvertisement(const std::vector<uint8_t>& encryptedPacket, std::vector<std::string>& packetsOut, std::vector<uint8_t>& cipherOut, std::vector<uint8_t>& hmacOut);

    /**
     * @brief Verifies a HelloHost message.
     * @param cipher Encrypted HelloHost.
     * @param hmac HMAC.
     * @param id Device ID to lookup.
     * @return True if verified.
     */
    bool verifyHelloHost(const std::vector<uint8_t>& cipher, const std::vector<uint8_t>& hmac, const std::string& id) const;

    /**
     * @brief Sets the currently connected EmotiBit device.
     * @param id Device ID.
     */
    void setConnectedDevice(const std::string& id);

    /**
     * @brief Clears the connected device information.
     */
    void clearConnectedDevice();

    /**
     * @brief Adds a discovered EmotiBit to internal repository.
     * @param id Device ID.
     * @param psk Pre-shared key.
     */
    void addDiscoveredEmotiBit(const std::string& id, const std::array<uint8_t, PSK_LENGTH>& psk);

    /**
     * @brief Retrieves a PSK from the local repository.
     * @param id Device ID.
     * @return Associated PSK.
     */
    std::array<uint8_t, PSK_LENGTH> getPskFromRepo(const std::string& id) const;

private:
    std::array<uint8_t, PSK_LENGTH> _pskOscilloscope;
    std::map<std::string, std::array<uint8_t, PSK_LENGTH>> _pskRepository;
    std::map<std::string, std::array<uint8_t, PSK_LENGTH>> _discoveredEmotiBits;
    std::string _connectedId;
    mutable std::mutex _mutex;
};
