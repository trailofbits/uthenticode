#include <parser-library/parse.h>
#include <uthenticode.h>

#include <cstdlib>

#include "gtest/gtest.h"
#include "helpers.h"

TEST(read_certs, handles_nullptr) {
  auto certs = uthenticode::read_certs(nullptr);

  EXPECT_EQ(certs.size(), 0);
}

TEST_F(NoAuthTest, read_certs) {
  auto certs = uthenticode::read_certs(pe);

  EXPECT_EQ(certs.size(), 0);
}

TEST_F(Auth32Test, read_certs) {
  auto certs = uthenticode::read_certs(pe);

  EXPECT_EQ(certs.size(), 1);
  EXPECT_TRUE(certs[0].as_signed_data().has_value());
}

TEST_F(Auth32PlusTest, read_certs) {
  auto certs = uthenticode::read_certs(pe);

  EXPECT_EQ(certs.size(), 1);
  EXPECT_TRUE(certs[0].as_signed_data().has_value());
}

TEST_F(NoAuthTest, get_checksums) {
  auto checksums = uthenticode::get_checksums(pe);

  EXPECT_EQ(checksums.size(), 0);
}

TEST_F(Auth32Test, get_checksums) {
  auto checksums = uthenticode::get_checksums(pe);

  EXPECT_EQ(checksums.size(), 1);
  EXPECT_EQ(std::get<uthenticode::checksum_kind>(checksums[0]), uthenticode::checksum_kind::SHA1);
}

TEST_F(Auth32PlusTest, get_checksums) {
  auto checksums = uthenticode::get_checksums(pe);

  EXPECT_EQ(checksums.size(), 1);
  EXPECT_EQ(std::get<uthenticode::checksum_kind>(checksums[0]), uthenticode::checksum_kind::SHA1);
}

TEST_F(NoAuthTest, calculate_checksum) {
  auto unk = uthenticode::calculate_checksum(pe, uthenticode::checksum_kind::UNKNOWN);
  EXPECT_TRUE(unk.empty());

  auto md5 = uthenticode::calculate_checksum(pe, uthenticode::checksum_kind::MD5);
  EXPECT_EQ(md5, "6f7ac8c1754fad04fba2a552a122e7");

  auto sha1 = uthenticode::calculate_checksum(pe, uthenticode::checksum_kind::SHA1);
  EXPECT_EQ(sha1, "4ba4c91418e28cb63b97cfde1cff95a91139");

  auto sha256 = uthenticode::calculate_checksum(pe, uthenticode::checksum_kind::SHA256);
  EXPECT_EQ(sha256, "e260f8a57faa823453bd9552506878fcbfb33203d9b606cb9a27e605a8d7b");
}

TEST_F(Auth32Test, calculate_checksum) {
  auto unk = uthenticode::calculate_checksum(pe, uthenticode::checksum_kind::UNKNOWN);
  EXPECT_TRUE(unk.empty());

  auto md5 = uthenticode::calculate_checksum(pe, uthenticode::checksum_kind::MD5);
  EXPECT_EQ(md5, "64c29391b57679b2973ac562cf64685d");

  auto sha1 = uthenticode::calculate_checksum(pe, uthenticode::checksum_kind::SHA1);
  EXPECT_EQ(sha1, "6663dd7c24fa84fce7f16eb2689952c06cfa22");

  auto sha256 = uthenticode::calculate_checksum(pe, uthenticode::checksum_kind::SHA256);
  EXPECT_EQ(sha256, "ea13992f99840f76dcac225dd1262edcec3254511b250a6d1e98d99fc48f815");
}

TEST_F(Auth32PlusTest, calculate_checksum) {
  auto unk = uthenticode::calculate_checksum(pe, uthenticode::checksum_kind::UNKNOWN);
  EXPECT_TRUE(unk.empty());

  auto md5 = uthenticode::calculate_checksum(pe, uthenticode::checksum_kind::MD5);
  EXPECT_EQ(md5, "ea235b77d552633c5a38974cef0e2b5");

  auto sha1 = uthenticode::calculate_checksum(pe, uthenticode::checksum_kind::SHA1);
  EXPECT_EQ(sha1, "2559e91a60953a5e16f965f5f88953a2cca5425");

  auto sha256 = uthenticode::calculate_checksum(pe, uthenticode::checksum_kind::SHA256);
  EXPECT_EQ(sha256, "5c823491c5991914aec971d9456d93d6cf2b8ee7e0ed7abcb7731d8ec073c0");
}

TEST(verify, handles_nullptr) {
  EXPECT_FALSE(uthenticode::verify(nullptr));
}

TEST_F(NoAuthTest, verify) {
  EXPECT_FALSE(uthenticode::verify(pe));
}

TEST_F(Auth32Test, verify) {
  EXPECT_TRUE(uthenticode::verify(pe));
}

TEST_F(Auth32PlusTest, verify) {
  EXPECT_TRUE(uthenticode::verify(pe));
}
