// EmotiBitSecurityHost.cpp
#include "EmotiBitSecurityHost.h"
#include <iostream>
#include <mbedtls/aes.h>
#include <mbedtls/md.h>
#include <ofMain.h>

// ========== Funcions comunes ==========

// Afegeix padding PKCS#7 al missatge per completar blocs AES
bool EmotiBitSecurityHost::padMessage(std::string& message, uint8_t blockSize) const {
    uint8_t padLen = blockSize - (message.length() % blockSize);
    message.append(padLen, static_cast<char>(padLen));
    return true;
}

// Elimina el padding PKCS#7 si és vàlid
bool EmotiBitSecurityHost::removePadding(std::vector<uint8_t>& data, uint8_t blockSize) const {
    if (data.empty()) {
        std::cout << "[removePadding] Error: Data buida." << std::endl;
        return false;
    }
    uint8_t padLen = data.back();
    if (padLen == 0 || padLen > blockSize) {
        std::cout << "[removePadding] Error: Padding no vàlid." << std::endl;
        return false;
    }
    data.resize(data.size() - padLen);
    return true;
}

// Xifra dades amb AES-128 ECB
std::vector<uint8_t> EmotiBitSecurityHost::aesEncrypt(const uint8_t* key, const uint8_t* input, size_t len) const {
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, key, 128);
    std::vector<uint8_t> output(len);
    for (size_t i = 0; i < len; i += AES_BLOCK_SIZE)
        mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, input + i, output.data() + i);
    mbedtls_aes_free(&aes);
    return output;
}

// Desxifra dades amb AES-128 ECB
std::vector<uint8_t> EmotiBitSecurityHost::aesDecrypt(const uint8_t* key, const uint8_t* input, size_t len) const {
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_dec(&aes, key, 128);
    std::vector<uint8_t> output(len);
    for (size_t i = 0; i < len; i += AES_BLOCK_SIZE)
        mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, input + i, output.data() + i);
    mbedtls_aes_free(&aes);
    return output;
}

// Calcula l'HMAC-SHA256 per unes dades amb clau
std::vector<uint8_t> EmotiBitSecurityHost::calculateHmac(const uint8_t* key, const uint8_t* data, size_t len) const {
    uint8_t hmac[HMAC_LEN];
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    if (mbedtls_md_setup(&ctx, md_info, 1) != 0) {
        std::cout << "[calculateHmac] Error en setup de mbedtls_md." << std::endl;
        return {};
    }
    mbedtls_md_hmac_starts(&ctx, key, PSK_LENGTH);
    mbedtls_md_hmac_update(&ctx, data, len);
    mbedtls_md_hmac_finish(&ctx, hmac);
    mbedtls_md_free(&ctx);
    return std::vector<uint8_t>(hmac, hmac + HMAC_LEN);
}

// Separa un paquet en dades xifrades i HMAC
bool EmotiBitSecurityHost::splitCipherAndHmac(const std::vector<uint8_t>& input, std::vector<uint8_t>& cipherOut, std::vector<uint8_t>& hmacOut) const {
    if (input.size() < HMAC_LEN) {
        std::cout << "[splitCipherAndHmac] Error: Input massa curt." << std::endl;
        return false;
    }
    size_t cipherLen = input.size() - HMAC_LEN;
    cipherOut.assign(input.begin(), input.begin() + cipherLen);
    hmacOut.assign(input.begin() + cipherLen, input.end());
    return true;
}

// Verifica la integritat d’un paquet només amb HMAC
bool EmotiBitSecurityHost::verifyOnly(const std::vector<uint8_t>& cipher, const std::vector<uint8_t>& hmac, const uint8_t* key) const {
    auto expected = calculateHmac(key, cipher.data(), cipher.size());
    if (std::memcmp(expected.data(), hmac.data(), HMAC_LEN) != 0) {
        std::cout << "[verifyOnly] Error: HMAC no coincideix." << std::endl;
        return false;
    }
    return true;
}

// Desxifra dades però no en verifica l’HMAC
bool EmotiBitSecurityHost::decryptOnly(const std::vector<uint8_t>& cipher, std::string& plaintextOut, const uint8_t* key) const {
    auto decrypted = aesDecrypt(key, cipher.data(), cipher.size());
    if (!removePadding(decrypted, AES_BLOCK_SIZE)) {
        std::cout << "[decryptOnly] Error en eliminació de padding." << std::endl;
        return false;
    }
    plaintextOut.assign(decrypted.begin(), decrypted.end());
    return true;
}

// Desxifra i valida HMAC del paquet complet
bool EmotiBitSecurityHost::decryptAndVerify(const std::vector<uint8_t>& input, std::string& plaintextOut, const uint8_t* key) const {
    std::vector<uint8_t> cipher, hmac;
    if (!splitCipherAndHmac(input, cipher, hmac)) {
        std::cout << "[decryptAndVerify] Error en split de cipher i hmac." << std::endl;
        return false;
    }
    if (!verifyOnly(cipher, hmac, key)) {
        std::cout << "[decryptAndVerify] Error en verificació de paquet." << std::endl;
        return false;
    }
    return decryptOnly(cipher, plaintextOut, key);
}

// Xifra i genera HMAC d’un missatge
bool EmotiBitSecurityHost::encryptAndSign(const std::string& message, const uint8_t* aesKey, const uint8_t* hmacKey, std::vector<uint8_t>& outEncrypted) const {
    std::string padded = message;
    padMessage(padded, AES_BLOCK_SIZE);
    auto cipher = aesEncrypt(aesKey, reinterpret_cast<const uint8_t*>(padded.data()), padded.size());
    auto hmac = calculateHmac(hmacKey, cipher.data(), cipher.size());
    outEncrypted = cipher;
    outEncrypted.insert(outEncrypted.end(), hmac.begin(), hmac.end());
    return true;
}

// Converteix un string hex en array de bytes
std::array<uint8_t, PSK_LENGTH> EmotiBitSecurityHost::hexStringToBytes(const std::string& hex) {
    std::array<uint8_t, PSK_LENGTH> bytes{};
    if (hex.size() != PSK_LENGTH * 2) {
        throw std::invalid_argument("Hex string must be 32 characters (16 bytes)");
    }
    for (size_t i = 0; i < PSK_LENGTH; ++i) {
        std::string byteString = hex.substr(2 * i, 2);
        bytes[i] = static_cast<uint8_t>(std::stoul(byteString, nullptr, 16));
    }
    return bytes;
}



// ========== Funcions específiques ==========

// Carrega claus precompartides (PSK) des d'una URL que retorna JSON
bool EmotiBitSecurityHost::loadKeysFromUrl(const std::string& url) {
    std::cout << "Loading keys from URL: " << url << std::endl;
    std::cout << std::endl;

    ofHttpResponse resp = ofLoadURL(url);
    if (resp.status != 200) {
        std::cout << "Failed to load URL. Status: " << resp.status << std::endl << std::endl;
        return false;
    }

    ofJson root;
    try {
        root = ofJson::parse(resp.data.getText());
    } catch (...) {
        std::cout << "Error parsing JSON from URL response." << std::endl << std::endl;
        return false;
    }

    if (!root.contains("status") || root["status"] != "success" || !root.contains("data")) {
        std::cout << "JSON missing 'status' or 'data' fields." << std::endl << std::endl;
        return false;
    }

    _pskRepository.clear();
    _discoveredEmotiBits.clear();
    _connectedId.clear();
    bool hasOscilloscopeKey = false;

    for (const auto& entry : root["data"]) {
        std::string id = entry.value("id", "");
        std::string hexKey = entry.value("secretkey", "");

        if (hexKey.size() != PSK_LENGTH * 2) {
            std::cout << "Skipping key with invalid hex size for ID: " << id << std::endl << std::endl;
            continue;
        }

        if (!std::all_of(hexKey.begin(), hexKey.end(), ::isxdigit)) {
            std::cout << "Key for ID " << id << " contains invalid hex characters." << std::endl;
            continue;
        }

        std::array<uint8_t, PSK_LENGTH> key;
        try {
            key = EmotiBitSecurityHost::hexStringToBytes(hexKey);
        } catch (const std::exception& e) {
            std::cout << "Invalid hex key for ID: " << id << ". Error: " << e.what() << std::endl << std::endl;
            continue;
        }

        if (id == "0") {
            _pskOscilloscope = key;
            hasOscilloscopeKey = true;
            std::cout << "Loaded oscilloscope key." << std::endl << std::endl;
        } else {
            _pskRepository[id] = key;
            std::cout << "Loaded key for device ID: " << id << std::endl << std::endl;
        }
    }

    return hasOscilloscopeKey;
}

// Utilitza la clau de l'oscil·loscopi per xifrar i signar el missatge
std::vector<uint8_t> EmotiBitSecurityHost::encryptAndSignWithOscilloscope(const std::string& plaintext) {
    std::vector<uint8_t> outEncrypted;
    encryptAndSign(plaintext, _pskOscilloscope.data(), _pskOscilloscope.data(), outEncrypted);
    return outEncrypted;
}

// Desxifra i valida un paquet del dispositiu connectat
bool EmotiBitSecurityHost::decryptAndVerifyFromConnected(const std::vector<uint8_t>& encryptedPacket, std::string& plaintextOut) {
    if (_connectedId.empty() || !_discoveredEmotiBits.count(_connectedId)) {
        std::cout << "No connected ID set or unknown device." << std::endl;
        return false;
    }
    return decryptAndVerify(encryptedPacket, plaintextOut, _discoveredEmotiBits.at(_connectedId).data());
}

// Verifica l'HMAC d'un paquet provinent del dispositiu connectat
bool EmotiBitSecurityHost::verifyConnectedPacket(const std::vector<uint8_t>& cipher, const std::vector<uint8_t>& hmac) const {
    if (_connectedId.empty() || !_discoveredEmotiBits.count(_connectedId)) {
        std::cout << "Verification failed: No connected device or PSK missing." << std::endl;
        return false;
    }
    return verifyOnly(cipher, hmac, _discoveredEmotiBits.at(_connectedId).data());
}

// Desxifra un paquet publicitari i retorna múltiples missatges
bool EmotiBitSecurityHost::decryptAdvertisement(const std::vector<uint8_t>& encryptedPacket, std::vector<std::string>& packetsOut, std::vector<uint8_t>& cipherOut, std::vector<uint8_t>& hmacOut) {
    if (!splitCipherAndHmac(encryptedPacket, cipherOut, hmacOut)) {
        std::cout << "Failed to split cipher and HMAC." << std::endl;
        return false;
    }
    std::string plaintext;
    if (!decryptOnly(cipherOut, plaintext, _pskOscilloscope.data())) {
        std::cout << "Failed to decrypt advertisement." << std::endl;
        return false;
    }
    packetsOut = ofSplitString(plaintext, "\n");
    return true;
}

// Verifica el paquet "hello" d'un dispositiu i el registra com descobert si és vàlid
bool EmotiBitSecurityHost::verifyHelloHost(const std::vector<uint8_t>& cipher, const std::vector<uint8_t>& hmac, const std::string& id) const {
    if (_pskRepository.count(id)) {
        bool valid = verifyOnly(cipher, hmac, _pskRepository.at(id).data());
        if (valid) {
            const_cast<EmotiBitSecurityHost*>(this)->addDiscoveredEmotiBit(id, _pskRepository.at(id));
        }
        return valid;
    }

    std::cout << "Aquest ID no s'ha trobat a la base de dades: " << id << std::endl;
    return false;
}

// Assigna el dispositiu connectat
void EmotiBitSecurityHost::setConnectedDevice(const std::string& id) {
    std::cout << "Setting connected device to ID: " << id << std::endl;
    _connectedId = id;
}

// Esborra l'identificador del dispositiu connectat
void EmotiBitSecurityHost::clearConnectedDevice() {
    std::cout << "Clearing connected device." << std::endl;
    _connectedId.clear();
}

// Desa un dispositiu descobert i la seva clau PSK
void EmotiBitSecurityHost::addDiscoveredEmotiBit(const std::string& id, const std::array<uint8_t, PSK_LENGTH>& psk) {
    std::lock_guard<std::mutex> lock(_mutex);
    _discoveredEmotiBits[id] = psk;
}

// Retorna la PSK d’un dispositiu des del repositori
std::array<uint8_t, PSK_LENGTH> EmotiBitSecurityHost::getPskFromRepo(const std::string& id) const {
    std::cout << "Retrieving PSK from repository for ID: " << id << std::endl;
    return _pskRepository.at(id);
}
