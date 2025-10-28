#include "crypto_guard_ctx.h"

#include <gtest/gtest.h>

#include <fstream>
#include <sstream>

TEST(CryptoGuardCtx, Encrypt1) {
    std::stringstream input{"One Two Three"};
    std::stringstream output{};

    std::stringstream expected{"9\xFDr\x9EM\xF4y\x99\x98SQ\xE1\x85\x89\x80\x1E"};

    CryptoGuard::CryptoGuardCtx ctx;
    ctx.EncryptFile(input, output, "12345678");

    ASSERT_EQ(output.str(), expected.str());
}

TEST(CryptoGuardCtx, Encrypt2) {
    std::stringstream input{"The quick brown fox jumps over the lazy dog"};
    std::stringstream output{};

    std::stringstream expected{};
    std::noskipws(expected);
    expected.write("\xB6\x96\xD5" "A'\0\xE1\x90\fL'\xE6\xFF\xAB\x17\x1C\xE8\x15x\xD5\xCC\xD8\x83H\xFD}\x9ERml:\x12\xB5\f\x9D\x1}\xD4\xB9<\xC1\xFF\xE2\xD6" "Fh\xE7" "b", 48);

    CryptoGuard::CryptoGuardCtx ctx;
    ctx.EncryptFile(input, output, "12345678");

    ASSERT_EQ(output.str(), expected.str());
}

TEST(CryptoGuardCtx, EncryptBadInput) {
    std::fstream input{"test.txt", std::ios::in};
    std::stringstream output;

    CryptoGuard::CryptoGuardCtx ctx;

    ASSERT_THROW(ctx.EncryptFile(input, output, "12345678"), std::exception);
}

TEST(CryptoGuardCtx, Decrypt1) {
    std::stringstream input{"9\xFDr\x9EM\xF4y\x99\x98SQ\xE1\x85\x89\x80\x1E"};
    std::stringstream output{};

    std::stringstream expected{"One Two Three"};

    CryptoGuard::CryptoGuardCtx ctx;
    ctx.DecryptFile(input, output, "12345678");

    ASSERT_EQ(output.str(), expected.str());
}

TEST(CryptoGuardCtx, Decrypt2) {
    std::stringstream input{};
    std::noskipws(input);
    input.write("\xB6\x96\xD5" "A'\0\xE1\x90\fL'\xE6\xFF\xAB\x17\x1C\xE8\x15x\xD5\xCC\xD8\x83H\xFD}\x9ERml:\x12\xB5\f\x9D\x1}\xD4\xB9<\xC1\xFF\xE2\xD6" "Fh\xE7" "b", 48);

    std::stringstream output{};

    std::stringstream expected{"The quick brown fox jumps over the lazy dog"};

    CryptoGuard::CryptoGuardCtx ctx;
    ctx.DecryptFile(input, output, "12345678");

    ASSERT_EQ(output.str(), expected.str());
}

TEST(CryptoGuardCtx, DecryptBadInput) {
    std::fstream input{"test.txt", std::ios::in};
    std::stringstream output;

    CryptoGuard::CryptoGuardCtx ctx;

    ASSERT_THROW(ctx.DecryptFile(input, output, "12345678"), std::exception);
}

TEST(CryptoGuardCtx, Checksum1) {
    std::stringstream input("The quick brown fox jumps over the lazy dog");

    std::string expected("d7a8fbb37d7809469ca9abcb082e4f8d5651e46d3cdb762d2d0bf37c9e592");

    CryptoGuard::CryptoGuardCtx ctx;

    ASSERT_EQ(ctx.CalculateChecksum(input), expected);
}

TEST(CryptoGuardCtx, Checksum2) {
    std::stringstream input("Съешь ещё этих мягких французских булок, да выпей чаю");

    std::string expected("ee5b3a26b27e15626db296ed1a3a1da9668dafe76181f3386c5ffeb47f60");

    CryptoGuard::CryptoGuardCtx ctx;

    ASSERT_EQ(ctx.CalculateChecksum(input), expected);
}

TEST(CryptoGuardCtx, Integration) {
    std::stringstream inputEncrypt("The quick brown fox jumps over the lazy dog");
    std::string inputEncryptChecksum("d7a8fbb37d7809469ca9abcb082e4f8d5651e46d3cdb762d2d0bf37c9e592");

    CryptoGuard::CryptoGuardCtx ctx;
    ASSERT_EQ(ctx.CalculateChecksum(inputEncrypt), inputEncryptChecksum);

    std::stringstream expectedEncrypted{};
    std::noskipws(expectedEncrypted);
    expectedEncrypted.write("\xB6\x96\xD5" "A'\0\xE1\x90\fL'\xE6\xFF\xAB\x17\x1C\xE8\x15x\xD5\xCC\xD8\x83H\xFD}\x9ERml:\x12\xB5\f\x9D\x1}\xD4\xB9<\xC1\xFF\xE2\xD6" "Fh\xE7" "b", 48);

    std::stringstream inputEncryptCopy("The quick brown fox jumps over the lazy dog");
    std::stringstream outputEncrypt{};
    ctx.EncryptFile(inputEncryptCopy, outputEncrypt, "12345678");
    ASSERT_EQ(outputEncrypt.str(), expectedEncrypted.str());

    std::stringstream outputDecrypt{};
    ctx.DecryptFile(outputEncrypt, outputDecrypt, "12345678");
    ASSERT_EQ(outputDecrypt.str(), inputEncrypt.str());

    ASSERT_EQ(inputEncryptChecksum, ctx.CalculateChecksum(outputDecrypt));
}
