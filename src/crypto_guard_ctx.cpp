#include "crypto_guard_ctx.h"

#include <openssl/err.h>
#include <openssl/evp.h>

#include <array>
#include <iostream>
#include <iterator>
#include <ranges>
#include <sstream>
#include <vector>

struct AesCipherParams {
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    int encrypt;                              // 1 for encryption, 0 for decryption
    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
};

namespace CryptoGuard {

class CryptoGuardCtx::Impl {
public:
    Impl();
    ~Impl();

    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) const;
    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) const;
    std::string CalculateChecksum(std::iostream &inStream) const;

private:
    AesCipherParams CreateChiperParamsFromPassword(std::string_view password) const;
};

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<Impl>()) {}

CryptoGuardCtx::~CryptoGuardCtx() = default;

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) const {
    pImpl_->EncryptFile(inStream, outStream, password);
}

void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) const {
    pImpl_->DecryptFile(inStream, outStream, password);
}

std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) const {
    return pImpl_->CalculateChecksum(inStream);
}

CryptoGuardCtx::Impl::Impl() { OpenSSL_add_all_algorithms(); }

CryptoGuardCtx::Impl::~Impl() { EVP_cleanup(); }

void CryptoGuardCtx::Impl::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) const {
    if (!inStream) {
        throw std::runtime_error("invalid input");
    }

    if (!outStream) {
        throw std::runtime_error("invalid output");
    }

    std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX *ctx) { EVP_CIPHER_CTX_free(ctx); })> ctx{
        EVP_CIPHER_CTX_new()};

    if (!ctx) {
        throw std::runtime_error(
            std::format("error: {}, code = {}\n", "bad cipher ctx initialization", ERR_get_error()));
    }

    auto params = CreateChiperParamsFromPassword(password);
    params.encrypt = 1;

    if (!EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt)) {
        throw std::runtime_error(
            std::format("error: {}, code = {}\n", "bad cipher process initialization", ERR_get_error()));
    }

    std::vector<unsigned char> inBuf{};
    std::noskipws(inStream);
    std::copy(std::istream_iterator<unsigned char>(inStream), std::istream_iterator<unsigned char>(),
              std::back_inserter(inBuf));

    std::vector<unsigned char> outBuf(inBuf.size() + EVP_MAX_BLOCK_LENGTH);
    int outLen{};

    if (!EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), inBuf.size())) {
        throw std::runtime_error(std::format("error: {}, code = {}\n", "bad cipher update", ERR_get_error()));
    }
    std::copy(outBuf.begin(), std::next(outBuf.begin(), outLen), std::ostream_iterator<unsigned char>(outStream));

    if (!EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen)) {
        throw std::runtime_error(std::format("error: {}, code = {}\n", "bad cipher finalization", ERR_get_error()));
    }
    std::copy(outBuf.begin(), std::next(outBuf.begin(), outLen), std::ostream_iterator<unsigned char>(outStream));
}

void CryptoGuardCtx::Impl::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) const {
    if (!inStream) {
        throw std::runtime_error("invalid input");
    }

    if (!outStream) {
        throw std::runtime_error("invalid output");
    }

    std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX *ctx) { EVP_CIPHER_CTX_free(ctx); })> ctx{
        EVP_CIPHER_CTX_new()};

    if (!ctx) {
        throw std::runtime_error(
            std::format("error: {}, code = {}\n", "bad cipher ctx initialization", ERR_get_error()));
    }

    auto params = CreateChiperParamsFromPassword(password);
    params.encrypt = 0;

    if (!EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt)) {
        throw std::runtime_error(
            std::format("error: {}, code = {}\n", "bad cipher process initialization", ERR_get_error()));
    }

    std::vector<unsigned char> inBuf{};
    std::noskipws(inStream);
    std::copy(std::istream_iterator<unsigned char>(inStream), std::istream_iterator<unsigned char>(),
              std::back_inserter(inBuf));

    std::vector<unsigned char> outBuf(inBuf.size() * 2);
    int outLen{};

    if (!EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), inBuf.size())) {
        throw std::runtime_error(std::format("error: {}, code = {}\n", "bad cipher update", ERR_get_error()));
    }
    std::copy(outBuf.begin(), std::next(outBuf.begin(), outLen), std::ostream_iterator<unsigned char>(outStream));

    if (!EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen)) {
        throw std::runtime_error(std::format("error: {}, code = {}\n", "bad cipher finalization", ERR_get_error()));
    }
    std::copy(outBuf.begin(), std::next(outBuf.begin(), outLen), std::ostream_iterator<unsigned char>(outStream));
}

std::string CryptoGuardCtx::Impl::CalculateChecksum(std::iostream &inStream) const {
    if (!inStream) {
        throw std::runtime_error("invalid input");
    }

    const auto *md = EVP_get_digestbyname("sha256");
    if (!md) {
        throw std::runtime_error("invalid algorithm");
    }

    std::unique_ptr<EVP_MD_CTX, decltype([](EVP_MD_CTX *ctx) { EVP_MD_CTX_free(ctx); })> ctx{EVP_MD_CTX_new()};

    if (!ctx) {
        throw std::runtime_error(std::format("error: {}, code = {}\n", "bad md ctx initialization", ERR_get_error()));
    }

    if (!EVP_DigestInit_ex2(ctx.get(), md, nullptr)) {
        throw std::runtime_error(
            std::format("error: {}, code = {}\n", "bad md process initialization", ERR_get_error()));
    }

    std::vector<unsigned char> inBuf{};
    std::noskipws(inStream);
    std::copy(std::istream_iterator<unsigned char>(inStream), std::istream_iterator<unsigned char>(),
              std::back_inserter(inBuf));

    if (!EVP_DigestUpdate(ctx.get(), inBuf.data(), inBuf.size())) {
        throw std::runtime_error(std::format("error: {}, code = {}\n", "bad md update", ERR_get_error()));
    }

    unsigned int mdLen{};
    std::array<unsigned char, 32> mdValue{};
    if (!EVP_DigestFinal_ex(ctx.get(), mdValue.data(), &mdLen)) {
        throw std::runtime_error(std::format("error: {}, code = {}\n", "bad cipher finalization", ERR_get_error()));
    }

    std::stringstream sstream{};
    for (auto c : mdValue) {
        sstream << std::hex << static_cast<int>(c);
    }

    return sstream.str();
}

AesCipherParams CryptoGuardCtx::Impl::CreateChiperParamsFromPassword(std::string_view password) const {
    AesCipherParams params;
    constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

    int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                params.key.data(), params.iv.data());

    if (result == 0) {
        throw std::runtime_error{"Failed to create a key from password"};
    }

    return params;
}

}  // namespace CryptoGuard
