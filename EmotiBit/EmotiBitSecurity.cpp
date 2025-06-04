// EmotiBitSecurity.cpp
#include "EmotiBitSecurity.h"


// ========== Common Utility Functions ==========

bool EmotiBitSecurity::padMessage(String& message, uint8_t blockSize) {
	uint8_t padLen = blockSize - (message.length() % blockSize);
	for (uint8_t i = 0; i < padLen; ++i) message += (char)padLen;
	return true;
}

bool EmotiBitSecurity::removePadding(std::vector<uint8_t>& data, uint8_t blockSize) {
	if (data.empty()) return false;
	uint8_t padLen = data.back();
	if (padLen == 0 || padLen > blockSize) return false;
	data.resize(data.size() - padLen);
	return true;
}

std::vector<uint8_t> EmotiBitSecurity::aesEncrypt(const uint8_t* key, const uint8_t* input, size_t len) {
	mbedtls_aes_context aes;
	mbedtls_aes_init(&aes);
	mbedtls_aes_setkey_enc(&aes, key, 128);
	std::vector<uint8_t> output(len);
	for (size_t i = 0; i < len; i += BLOCK_SIZE)
	mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, input + i, output.data() + i);
	mbedtls_aes_free(&aes);
	return output;
}

std::vector<uint8_t> EmotiBitSecurity::aesDecrypt(const uint8_t* key, const uint8_t* input, size_t len) {
	mbedtls_aes_context aes;
	mbedtls_aes_init(&aes);
	mbedtls_aes_setkey_dec(&aes, key, 128);
	std::vector<uint8_t> output(len);
	for (size_t i = 0; i < len; i += BLOCK_SIZE)
	mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, input + i, output.data() + i);
	mbedtls_aes_free(&aes);
	return output;
}

std::vector<uint8_t> EmotiBitSecurity::calculateHmac(const uint8_t* key, const uint8_t* data, size_t len) {
	uint8_t hmac[HMAC_LEN];
	const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	mbedtls_md_context_t ctx;
	mbedtls_md_init(&ctx);
	mbedtls_md_setup(&ctx, md_info, 1);
	mbedtls_md_hmac_starts(&ctx, key, PSK_LENGTH);
	mbedtls_md_hmac_update(&ctx, data, len);
	mbedtls_md_hmac_finish(&ctx, hmac);
	mbedtls_md_free(&ctx);
	return std::vector<uint8_t>(hmac, hmac + HMAC_LEN);
}

bool EmotiBitSecurity::splitCipherAndHmac(const std::vector<uint8_t>& input, std::vector<uint8_t>& cipherOut, std::vector<uint8_t>& hmacOut) {
	if (input.size() < HMAC_LEN){
		 return false;
		 }
	size_t cipherLen = input.size() - HMAC_LEN;
	cipherOut.assign(input.begin(), input.begin() + cipherLen);
	hmacOut.assign(input.begin() + cipherLen, input.end());
	return true;
}

bool EmotiBitSecurity::verifyOnly(const std::vector<uint8_t>& cipher, const std::vector<uint8_t>& hmac, const uint8_t* key) {
	auto expected = calculateHmac(key, cipher.data(), cipher.size());
	return memcmp(expected.data(), hmac.data(), HMAC_LEN) == 0;
}

bool EmotiBitSecurity::decryptOnly(const std::vector<uint8_t>& cipher, String& plaintextOut, const uint8_t* key) {
	auto decrypted = aesDecrypt(key, cipher.data(), cipher.size());
	if (!removePadding(decrypted, BLOCK_SIZE)) return false;
	plaintextOut = String((char*)decrypted.data());
	return true;
}

bool EmotiBitSecurity::decryptAndVerify(const std::vector<uint8_t>& input, String& plaintextOut, const uint8_t* key) {
	std::vector<uint8_t> cipher, hmac;
	if (!splitCipherAndHmac(input, cipher, hmac)) return false;
	if (!verifyOnly(cipher, hmac, key)) {
		return false;
		}
	return decryptOnly(cipher, plaintextOut, key);
}

std::array<uint8_t, PSK_LENGTH> EmotiBitSecurity::hexStringToBytes(const String& hex) {
	std::array<uint8_t, PSK_LENGTH> bytes{};
	if (hex.length() != PSK_LENGTH * 2) {
		throw std::invalid_argument("Hex string must be 32 characters (16 bytes)");
	}
	for (size_t i = 0; i < PSK_LENGTH; ++i) {
		String byteStr = hex.substring(i * 2, i * 2 + 2);
		bytes[i] = static_cast<uint8_t>(strtol(byteStr.c_str(), nullptr, 16));
	}
	return bytes;
}

// ========== Key Loading ==========

bool EmotiBitSecurity::loadKeysFromFile(const String& path) {
	File f = SD.open(path, FILE_READ);
	if (!f) return false;

	String keyEbStr, keyOscStr;
	while (f.available()) {
		String line = f.readStringUntil('\n');
		line.trim();
		if (line.startsWith("t1=")) keyEbStr = line.substring(3);
		else if (line.startsWith("t2=")) keyOscStr = line.substring(3);
	}
	f.close();

	if (keyEbStr.length() != PSK_LENGTH * 2 || keyOscStr.length() != PSK_LENGTH * 2) return false;

	for (char c : keyEbStr + keyOscStr) {
		if (!isxdigit(c)) return false;
	}

	try {
		auto ebKey = EmotiBitSecurity::hexStringToBytes(keyEbStr);
		auto oscKey = EmotiBitSecurity::hexStringToBytes(keyOscStr);
		memcpy(_psk_eb, ebKey.data(), PSK_LENGTH);
		memcpy(_psk_osc, oscKey.data(), PSK_LENGTH);
	} catch (...) {
		return false;
	}

	return true;
}

// ========== Combined Operations ==========

bool EmotiBitSecurity::encryptAndSignGeneric(const String& message, const uint8_t* aesKey, const uint8_t* hmacKey, std::vector<uint8_t>& outEncrypted) {
	String padded = message;
	padMessage(padded, BLOCK_SIZE);
	auto cipher = aesEncrypt(aesKey, (const uint8_t*)padded.c_str(), padded.length());
	auto hmac = calculateHmac(hmacKey, cipher.data(), cipher.size());
	outEncrypted = cipher;
	outEncrypted.insert(outEncrypted.end(), hmac.begin(), hmac.end());
	return true;
}

bool EmotiBitSecurity::encryptAndSignControl(const String& message, std::vector<uint8_t>& outEncrypted) {
	return encryptAndSignGeneric(message, _psk_osc, _psk_eb, outEncrypted);
}

bool EmotiBitSecurity::encryptAndSignData(const String& message, std::vector<uint8_t>& outEncrypted) {
	return encryptAndSignGeneric(message, _psk_eb, _psk_eb, outEncrypted);
}

bool EmotiBitSecurity::decryptAndVerifyHMAC(const std::vector<uint8_t>& input, String& plaintextOut) {
	return decryptAndVerify(input, plaintextOut, _psk_osc);
}
