#include <parser-library/parse.h>
#include <uthenticode.h>

#include <cstdlib>

#include "gtest/gtest.h"
#include "helpers.h"

TEST_F(Auth32Test, SignedData_properties) {
  auto certs = uthenticode::read_certs(pe);
  auto signed_data = certs[0].as_signed_data();

  ASSERT_TRUE(signed_data.has_value());

  ASSERT_EQ(signed_data->get_signers().size(), 1);
  ASSERT_EQ(signed_data->get_certificates().size(), 1);
  ASSERT_TRUE(signed_data->verify_signature());

  auto checksum = signed_data->get_checksum();
  ASSERT_EQ(std::get<uthenticode::checksum_kind>(checksum), uthenticode::checksum_kind::SHA1);
  ASSERT_EQ(std::get<std::string>(checksum), "6663dd7c24fa84fce7f16eb2689952c06cfa22");
}

TEST_F(Auth32PlusTest, SignedData_properties) {
  auto certs = uthenticode::read_certs(pe);
  auto signed_data = certs[0].as_signed_data();

  ASSERT_EQ(signed_data->get_signers().size(), 1);
  ASSERT_EQ(signed_data->get_certificates().size(), 1);
  ASSERT_TRUE(signed_data.has_value());

  ASSERT_TRUE(signed_data->verify_signature());

  auto checksum = signed_data->get_checksum();
  ASSERT_EQ(std::get<uthenticode::checksum_kind>(checksum), uthenticode::checksum_kind::SHA1);
  ASSERT_EQ(std::get<std::string>(checksum), "2559e91a60953a5e16f965f5f88953a2cca5425");
}
