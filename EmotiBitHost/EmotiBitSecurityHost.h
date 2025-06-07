// ==========================================================================================
//  EmotiBitSecurityHost.h
//
//  Descripció:
//  Classe per gestionar operacions criptogràfiques a l'host per a dispositius EmotiBit.
//  Inclou funcionalitats per xifrat i desxifrat AES, HMAC, padding de missatges,
//  gestió de claus precompartides (PSK) i verificació d'integritat.
//
// ==========================================================================================

#pragma once

#include <vector>
#include <string>
#include <map>
#include <array>
#include <mutex>

#define PSK_LENGTH 16
#define AES_BLOCK_SIZE 16
#define HMAC_LEN 32

class EmotiBitSecurityHost {
public:
    // ================= Funcions comunes =================

    /**
     * Afegeix padding PKCS#7 a un missatge perquè sigui múltiple de blockSize.
     * @param message Missatge original que es modificarà.
     * @param blockSize Mida del bloc (habitualment 16).
     * @return true si s'ha aplicat correctament.
     */
    bool padMessage(std::string& message, uint8_t blockSize) const;

    /**
     * Elimina el padding PKCS#7 d'un vector de dades.
     * @param data Dades a despaddejar.
     * @param blockSize Mida del bloc original.
     * @return true si el padding era vàlid i s'ha eliminat.
     */
    bool removePadding(std::vector<uint8_t>& data, uint8_t blockSize) const;

    /**
     * Xifra dades amb AES-128 en mode ECB.
     * @param key Clau AES de 16 bytes.
     * @param input Dades a xifrar.
     * @param len Longitud de les dades.
     * @return Vector amb les dades xifrades.
     */
    std::vector<uint8_t> aesEncrypt(const uint8_t* key, const uint8_t* input, size_t len) const;

    /**
     * Desxifra dades amb AES-128 en mode ECB.
     * @param key Clau AES de 16 bytes.
     * @param input Dades xifrades.
     * @param len Longitud de les dades.
     * @return Vector amb les dades desxifrades.
     */
    std::vector<uint8_t> aesDecrypt(const uint8_t* key, const uint8_t* input, size_t len) const;

    /**
     * Calcula un HMAC-SHA256 sobre unes dades donades.
     * @param key Clau HMAC.
     * @param data Dades d'entrada.
     * @param len Longitud de les dades.
     * @return Vector amb l'HMAC.
     */
    std::vector<uint8_t> calculateHmac(const uint8_t* key, const uint8_t* data, size_t len) const;

    /**
     * Separa un vector d'entrada en xifrat i HMAC.
     * @param input Vector combinat (xifrat + HMAC).
     * @param cipherOut Sortida del xifrat.
     * @param hmacOut Sortida del HMAC.
     * @return true si la separació ha tingut èxit.
     */
    bool splitCipherAndHmac(const std::vector<uint8_t>& input, std::vector<uint8_t>& cipherOut, std::vector<uint8_t>& hmacOut) const;

    /**
     * Verifica un paquet xifrat utilitzant un HMAC proporcionat.
     * @param cipher Dades xifrades.
     * @param hmac HMAC calculat.
     * @param key Clau HMAC.
     * @return true si la verificació és correcta.
     */
    bool verifyOnly(const std::vector<uint8_t>& cipher, const std::vector<uint8_t>& hmac, const uint8_t* key) const;

    /**
     * Desxifra un paquet però no en verifica l'HMAC.
     * @param cipher Dades xifrades.
     * @param plaintextOut Sortida del missatge pla.
     * @param key Clau AES.
     * @return true si la desxifració ha tingut èxit.
     */
    bool decryptOnly(const std::vector<uint8_t>& cipher, std::string& plaintextOut, const uint8_t* key) const;

    /**
     * Desxifra i verifica la integritat del paquet xifrat.
     * @param input Paquet complet (xifrat + HMAC).
     * @param plaintextOut Missatge pla desxifrat.
     * @param key Clau AES i HMAC.
     * @return true si l'HMAC és vàlid i el contingut desxifrat.
     */
    bool decryptAndVerify(const std::vector<uint8_t>& input, std::string& plaintextOut, const uint8_t* key) const;

    /**
     * Xifra i signa un missatge amb AES i HMAC.
     * @param message Missatge pla.
     * @param aesKey Clau de xifrat.
     * @param hmacKey Clau de signatura.
     * @param outEncrypted Sortida amb xifrat + HMAC.
     * @return true si ha anat bé.
     */
    bool encryptAndSign(const std::string& message, const uint8_t* aesKey, const uint8_t* hmacKey, std::vector<uint8_t>& outEncrypted) const;

    /**
     * Converteix una cadena hexadecimal en una array de bytes.
     * @param hex Cadena hex (32 caràcters per 16 bytes).
     * @return Array de 16 bytes.
     */
    std::array<uint8_t, PSK_LENGTH> hexStringToBytes(const std::string& hex);

    // ================= Funcions específiques =================

    /**
     * Carrega claus des d’una URL (per exemple, fitxer JSON).
     * @param url Ruta o enllaç.
     * @return true si s’ha carregat correctament.
     */
    bool loadKeysFromUrl(const std::string& url);

    /**
     * Xifra un missatge per enviar-lo a l’oscil·loscopi.
     * @param plaintext Missatge pla.
     * @return Vector xifrat signat.
     */
    std::vector<uint8_t> encryptAndSignWithOscilloscope(const std::string& plaintext);

    /**
     * Desxifra i valida un paquet rebut del dispositiu connectat.
     * @param encryptedPacket Paquet xifrat complet.
     * @param plaintextOut Resultat desxifrat.
     * @return true si ha estat vàlid.
     */
    bool decryptAndVerifyFromConnected(const std::vector<uint8_t>& encryptedPacket, std::string& plaintextOut);

    /**
     * Verifica només l’HMAC d’un paquet connectat.
     * @param cipher Dades xifrades.
     * @param hmac HMAC.
     * @return true si és vàlid.
     */
    bool verifyConnectedPacket(const std::vector<uint8_t>& cipher, const std::vector<uint8_t>& hmac) const;

    /**
     * Desxifra paquets d’anuncis i retorna múltiples missatges.
     * @param encryptedPacket Paquet original.
     * @param packetsOut Vector de missatges desxifrats.
     * @param cipherOut Part xifrada separada.
     * @param hmacOut HMAC separat.
     * @return true si tot és vàlid.
     */
    bool decryptAdvertisement(const std::vector<uint8_t>& encryptedPacket, std::vector<std::string>& packetsOut, std::vector<uint8_t>& cipherOut, std::vector<uint8_t>& hmacOut);

    /**
     * Verifica un paquet de tipus "hello" d’un EmotiBit.
     * @param cipher Contingut xifrat.
     * @param hmac HMAC del paquet.
     * @param id Identificador del dispositiu.
     * @return true si és vàlid.
     */
    bool verifyHelloHost(const std::vector<uint8_t>& cipher, const std::vector<uint8_t>& hmac, const std::string& id) const;

    /**
     * Defineix quin dispositiu està connectat actualment.
     * @param id Identificador del dispositiu.
     */
    void setConnectedDevice(const std::string& id);

    /**
     * Neteja el dispositiu connectat.
     */
    void clearConnectedDevice();

    /**
     * Afegeix un dispositiu descobert amb la seva PSK.
     * @param id Identificador.
     * @param psk Clau precompartida.
     */
    void addDiscoveredEmotiBit(const std::string& id, const std::array<uint8_t, PSK_LENGTH>& psk);

    /**
     * Recupera la PSK d’un dispositiu conegut.
     * @param id Identificador.
     * @return PSK associada.
     */
    std::array<uint8_t, PSK_LENGTH> getPskFromRepo(const std::string& id) const;

private:
    std::array<uint8_t, PSK_LENGTH> _pskOscilloscope;
    std::map<std::string, std::array<uint8_t, PSK_LENGTH>> _pskRepository;
    std::map<std::string, std::array<uint8_t, PSK_LENGTH>> _discoveredEmotiBits;
    std::string _connectedId;
    mutable std::mutex _mutex;
};
