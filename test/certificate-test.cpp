#include <parser-library/parse.h>
#include <uthenticode.h>

#include <cstdlib>

#include "gtest/gtest.h"
#include "helpers.h"

TEST_F(Auth32Test, Certificate_properties) {
  auto certs = uthenticode::read_certs(pe);
  auto signed_data = certs[0].as_signed_data();

  ASSERT_TRUE(signed_data.has_value());

  auto signers = signed_data->get_signers();
  ASSERT_EQ(signers[0].get_subject(), "/CN=contact@trailofbits.com");
  ASSERT_EQ(signers[0].get_issuer(), "/CN=contact@trailofbits.com");
  ASSERT_EQ(signers[0].get_serial_number(), "4B2A0A5FE84F83BE4B5F587EC325FDA3");

  auto certificates = signed_data->get_certificates();
  ASSERT_EQ(certificates[0].get_subject(), "/CN=contact@trailofbits.com");
  ASSERT_EQ(certificates[0].get_issuer(), "/CN=contact@trailofbits.com");
  ASSERT_EQ(certificates[0].get_serial_number(), "4B2A0A5FE84F83BE4B5F587EC325FDA3");
}

TEST_F(Auth32PlusTest, Certificate_properties) {
  auto certs = uthenticode::read_certs(pe);
  auto signed_data = certs[0].as_signed_data();

  ASSERT_TRUE(signed_data.has_value());

  auto signers = signed_data->get_signers();
  ASSERT_EQ(signers[0].get_subject(), "/CN=contact@trailofbits.com");
  ASSERT_EQ(signers[0].get_issuer(), "/CN=contact@trailofbits.com");
  ASSERT_EQ(signers[0].get_serial_number(), "5C01626BE30E6696475724EFA09135F3");

  auto certificates = signed_data->get_certificates();
  ASSERT_EQ(certificates[0].get_subject(), "/CN=contact@trailofbits.com");
  ASSERT_EQ(certificates[0].get_issuer(), "/CN=contact@trailofbits.com");
  ASSERT_EQ(certificates[0].get_serial_number(), "5C01626BE30E6696475724EFA09135F3");
}

TEST_F(AuthNest32Test, Certificate_properties_nested) {
  auto certs = uthenticode::read_certs(pe);
  auto signed_data = certs[0].as_signed_data();

  ASSERT_TRUE(signed_data.has_value());

  auto signers = signed_data->get_signers();
  ASSERT_EQ(signers[0].get_subject(), "/CN=A SHA-1 cert");
  ASSERT_EQ(signers[0].get_issuer(), "/CN=A SHA-1 cert");
  ASSERT_EQ(signers[0].get_serial_number(), "103EE193544680954387616BB5ECA399");

  auto certificates = signed_data->get_certificates();
  ASSERT_EQ(certificates[0].get_subject(), "/CN=A SHA-1 cert");
  ASSERT_EQ(certificates[0].get_issuer(), "/CN=A SHA-1 cert");
  ASSERT_EQ(certificates[0].get_serial_number(), "103EE193544680954387616BB5ECA399");

  auto nested_signed_data = signed_data->get_nested_signed_data();

  ASSERT_TRUE(nested_signed_data.has_value());

  auto nested_signers = nested_signed_data->get_signers();
  ASSERT_EQ(nested_signers[0].get_subject(), "/CN=A SHA-256 cert");
  ASSERT_EQ(nested_signers[0].get_issuer(), "/CN=A SHA-256 cert");
  ASSERT_EQ(nested_signers[0].get_serial_number(), "2D96C54BA915F7B04781D80A799534B1");

  auto nested_certificates = nested_signed_data->get_certificates();
  ASSERT_EQ(nested_certificates[0].get_subject(), "/CN=A SHA-256 cert");
  ASSERT_EQ(nested_certificates[0].get_issuer(), "/CN=A SHA-256 cert");
  ASSERT_EQ(nested_certificates[0].get_serial_number(), "2D96C54BA915F7B04781D80A799534B1");
}

TEST_F(AuthNest32PlusTest, Certificate_properties_nested) {
  auto certs = uthenticode::read_certs(pe);
  auto signed_data = certs[0].as_signed_data();

  ASSERT_TRUE(signed_data.has_value());

  auto signers = signed_data->get_signers();
  ASSERT_EQ(signers[0].get_subject(), "/CN=A SHA-1 cert");
  ASSERT_EQ(signers[0].get_issuer(), "/CN=A SHA-1 cert");
  ASSERT_EQ(signers[0].get_serial_number(), "1DFA12996D33C09D499BE8489BE35DE5");

  auto certificates = signed_data->get_certificates();
  ASSERT_EQ(certificates[0].get_subject(), "/CN=A SHA-1 cert");
  ASSERT_EQ(certificates[0].get_issuer(), "/CN=A SHA-1 cert");
  ASSERT_EQ(certificates[0].get_serial_number(), "1DFA12996D33C09D499BE8489BE35DE5");

  auto nested_signed_data = signed_data->get_nested_signed_data();

  ASSERT_TRUE(nested_signed_data.has_value());

  auto nested_signers = nested_signed_data->get_signers();
  ASSERT_EQ(nested_signers[0].get_subject(), "/CN=A SHA-256 cert");
  ASSERT_EQ(nested_signers[0].get_issuer(), "/CN=A SHA-256 cert");
  ASSERT_EQ(nested_signers[0].get_serial_number(), "24669C98D6ED318540F4953CD30250AB");

  auto nested_certificates = nested_signed_data->get_certificates();
  ASSERT_EQ(nested_certificates[0].get_subject(), "/CN=A SHA-256 cert");
  ASSERT_EQ(nested_certificates[0].get_issuer(), "/CN=A SHA-256 cert");
  ASSERT_EQ(nested_certificates[0].get_serial_number(), "24669C98D6ED318540F4953CD30250AB");
}
