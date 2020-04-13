#pragma once

class NoAuthTest : public ::testing::Test {
 protected:
  void SetUp() override {
    auto *file = SMOLVERIFY_TEST_ASSETS "/32/pegoat.exe";

    pe = peparse::ParsePEFromFile(file);
    ASSERT_TRUE(pe != nullptr);
  }

  void TearDown() override {
    peparse::DestructParsedPE(pe);
  }

  peparse::parsed_pe *pe{nullptr};
};

class Auth32Test : public ::testing::Test {
 protected:
  void SetUp() override {
    auto *file = SMOLVERIFY_TEST_ASSETS "/32/pegoat-authenticode.exe";

    pe = peparse::ParsePEFromFile(file);
    ASSERT_TRUE(pe != nullptr);
  }

  void TearDown() override {
    peparse::DestructParsedPE(pe);
  }

  peparse::parsed_pe *pe{nullptr};
};

class Auth32PlusTest : public ::testing::Test {
 protected:
  void SetUp() override {
    auto *file = SMOLVERIFY_TEST_ASSETS "/64/pegoat-authenticode.exe";

    pe = peparse::ParsePEFromFile(file);
    ASSERT_TRUE(pe != nullptr);
  }

  void TearDown() override {
  }

  peparse::parsed_pe *pe{nullptr};
};
