#include <parser-library/parse.h>
#include <smolverify.h>

#include <cstdlib>

#include "gtest/gtest.h"
#include "helpers.h"

TEST_F(Auth32Test, Certificate_properties) {
  auto certs = smolverify::read_certs(pe);
  auto signed_data = certs[0].as_signed_data();

  ASSERT_TRUE(signed_data.has_value());

  auto signers = signed_data->get_signers();
  ASSERT_EQ(signers[0].get_subject(), "/CN=contact@trailofbits.com");
  ASSERT_EQ(signers[0].get_issuer(), "/CN=contact@trailofbits.com");
  ASSERT_EQ(signers[0].get_serial_number(), "4B2A0A5FE84F83BE4B5F587EC325FDA3");

  auto certificates = signed_data->get_certificates();
}

TEST_F(Auth32PlusTest, Certificate_properties) {
  auto certs = smolverify::read_certs(pe);
  auto signed_data = certs[0].as_signed_data();

  ASSERT_TRUE(signed_data.has_value());

  auto signers = signed_data->get_signers();
  ASSERT_EQ(signers[0].get_subject(), "/CN=contact@trailofbits.com");
  ASSERT_EQ(signers[0].get_issuer(), "/CN=contact@trailofbits.com");
  ASSERT_EQ(signers[0].get_serial_number(), "5C01626BE30E6696475724EFA09135F3");

  auto certificates = signed_data->get_certificates();
}
