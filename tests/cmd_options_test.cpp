#include "cmd_options.h"

#include <gtest/gtest.h>

#include <fstream>

using namespace CryptoGuard;

TEST(CmdOptionsCommand, Encrypt) {
    ProgramOptions options{};
    constexpr static std::array argv = {"", "--command=encrypt", "--input=."};
    options.Parse(3, argv.data());

    ASSERT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::ENCRYPT);
}

TEST(CmdOptionsCommand, Decrypt) {
    ProgramOptions options{};
    constexpr static std::array argv = {"", "--command=decrypt", "--input=."};
    options.Parse(3, argv.data());

    ASSERT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::DECRYPT);
}

TEST(CmdOptionsCommand, Checksum) {
    ProgramOptions options{};
    constexpr static std::array argv = {"", "--command=checksum", "--input=."};
    options.Parse(3, argv.data());

    ASSERT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::CHECKSUM);
}

TEST(CmdOptionsCommand, NonExistingCommand) {
    ProgramOptions options{};
    constexpr static std::array argv = {"", "--command=something", "--input=."};

    ASSERT_THROW(options.Parse(3, argv.data()), std::exception);
}

TEST(CmdOptionsCommand, NoCommand) {
    ProgramOptions options{};
    constexpr static std::array argv = {"", "--input=."};

    ASSERT_THROW(options.Parse(2, argv.data()), std::exception);
}

class ArgsTest : public ::testing::Test {
protected:
    void SetUp() override {
        file_.open(filename_);
        file_.close();
    }

protected:
    std::string filename_{"file.txt"};
    std::ofstream file_;
};

TEST_F(ArgsTest, InputFileValue) {
    ProgramOptions options{};
    constexpr static std::array argv = {"", "--command=encrypt", "--input=file.txt"};
    options.Parse(3, argv.data());

    ASSERT_EQ(options.GetInputFile(), "file.txt");
}

TEST_F(ArgsTest, OutputFileValue) {
    ProgramOptions options{};
    constexpr static std::array argv = {"", "--command=encrypt", "--input=file.txt", "--output=output.txt"};
    options.Parse(4, argv.data());

    ASSERT_EQ(options.GetOutputFile(), "output.txt");
}

TEST_F(ArgsTest, PasswordValue) {
    ProgramOptions options{};
    constexpr static std::array argv = {"", "--command=encrypt", "--input=file.txt", "--output=output.txt",
                                        "--password=12345678"};
    options.Parse(5, argv.data());

    ASSERT_EQ(options.GetPassword(), "12345678");
}
