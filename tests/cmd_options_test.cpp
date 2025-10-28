#include "cmd_options.h"

#include <gtest/gtest.h>

using namespace CryptoGuard;

TEST(CmdOptionsCommand, Encrypt) {
    ProgramOptions options{};
    char *argv[] = {"", "--command=encrypt", "--input=."};
    options.Parse(3, argv);

    ASSERT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::ENCRYPT);
}

TEST(CmdOptionsCommand, Decrypt) {
    ProgramOptions options{};
    char *argv[] = {"", "--command=decrypt", "--input=."};
    options.Parse(3, argv);

    ASSERT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::DECRYPT);
}

TEST(CmdOptionsCommand, Checksum) {
    ProgramOptions options{};
    char *argv[] = {"", "--command=checksum", "--input=."};
    options.Parse(3, argv);

    ASSERT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::CHECKSUM);
}

TEST(CmdOptionsCommand, NonExistingCommand) {
    ProgramOptions options{};
    char *argv[] = {"", "--command=something", "--input=."};

    ASSERT_THROW(options.Parse(3, argv), std::exception);
}

TEST(CmdOptionsCommand, NoCommand) {
    ProgramOptions options{};
    char *argv[] = {"", "--input=."};

    ASSERT_THROW(options.Parse(2, argv), std::exception);
}

TEST(ProgramOptions, InputFileValue) {
    ProgramOptions options{};
    char *argv[] = {"", "--command=encrypt", "--input=file.txt"};
    options.Parse(3, argv);

    ASSERT_EQ(options.GetInputFile(), std::string{"file.txt"});
}

TEST(ProgramOptions, OutputFileValue) {
    ProgramOptions options{};
    char *argv[] = {"", "--command=encrypt", "--input=file.txt", "--output=output.txt"};
    options.Parse(4, argv);

    ASSERT_EQ(options.GetOutputFile(), std::string{"output.txt"});
}

TEST(ProgramOptions, PasswordValue) {
    ProgramOptions options{};
    char *argv[] = {"", "--command=encrypt", "--input=file.txt", "--output=output.txt", "--password=12345678"};
    options.Parse(5, argv);

    ASSERT_EQ(options.GetPassword(), std::string{"12345678"});
}
