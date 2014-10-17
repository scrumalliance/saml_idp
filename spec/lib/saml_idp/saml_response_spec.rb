require 'spec_helper'
module SamlIdp
  describe SamlResponse do
    let (:signature_opts) do
      {
        cert: SamlIdp.config.x509_certificate,
        key: SamlIdp.config.secret_key,
        signature_alg: SamlIdp.config.signature_alg,
        digest_alg: SamlIdp.config.digest_alg,
      }
    end

    let (:encryption_opts) do
      {
        cert: Default::SERVICE_PROVIDER_CERT,
        block_encryption: 'aes256-cbc',
        key_transport: 'rsa-oaep-mgf1p',
      }
    end

    it "has a valid unencrypted build" do
     response = SamlResponse.new("a_reference_id",
                                  "a_responce_id",
                                  "http://localhost",
                                  "a_name_id",
                                  "http://localhost/audience",
                                  "a_saml_request_id",
                                  "http://localhost/acs",
                                  signature_opts,
                                  {}, # Empty encryption opts means don't encrypt.
                                  Saml::XML::Namespaces::AuthnContext::ClassRef::PASSWORD)
      # Don't throw.
      doc = response.build

      assertion_nodeset = doc.xpath('//saml:Assertion',
                                              'saml' => Saml::XML::Namespaces::ASSERTION)
      expect(assertion_nodeset.length).to be(1)
    end

    it "has a valid encrypted build" do
     response = SamlResponse.new("a_reference_id",
                                  "a_responce_id",
                                  "http://localhost",
                                  "a_name_id",
                                  "http://localhost/audience",
                                  "a_saml_request_id",
                                  "http://localhost/acs",
                                  signature_opts,
                                  encryption_opts,
                                  Saml::XML::Namespaces::AuthnContext::ClassRef::PASSWORD)
      # Don't throw.
      doc = response.build

      encrypted_assertion_nodeset = doc.xpath('//saml:EncryptedAssertion',
                                              'saml' => Saml::XML::Namespaces::ASSERTION)
      expect(encrypted_assertion_nodeset.length).to be(1)
    end
  end
end
