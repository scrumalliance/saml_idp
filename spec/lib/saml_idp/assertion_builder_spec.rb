require 'spec_helper'

module SamlIdp
  describe AssertionBuilder do
    let (:signature_opts) do
      {
        cert: SamlIdp.config.x509_certificate,
        key: SamlIdp.config.secret_key,
        signature_alg: SamlIdp.config.signature_alg,
        digest_alg: SamlIdp.config.digest_alg
      }
    end

    let (:encryption_opts) do
      {
        key: OpenSSL::X509::Certificate.new(Default::SERVICE_PROVIDER[:cert]).public_key.to_pem,
        block_encryption: Default::SERVICE_PROVIDER[:block_encryption],
        key_transport: Default::SERVICE_PROVIDER[:key_transport],
      }
    end

    subject { described_class.new(
      "abc",
      "http://sportngin.com",
      "jon.phenow@sportngin.com",
      "http://example.com",
      "_123",
      "http://saml.acs.url",
      signature_opts,
      encryption_opts,
      Saml::XML::Namespaces::AuthnContext::ClassRef::PASSWORD,
    )}

    it "builds a well-formed, unsigned, unencrypted SAML Assertion" do
      Timecop.travel(Time.zone.local(2010, 6, 1, 13, 0, 0)) do
        assertion = subject.build_assertion
        expect(assertion).to pass_validation(
          fixture_path('schemas/saml-schema-assertion-2.0.xsd'))
        # TODO(awong): Now that there is schema validation, check for
        # specific content propagtion using xpath rather than a golden file.
        expect(assertion).to be_equivalent_to(
          Nokogiri::XML(fixture('assertion-simple.xml'))
        ).respecting_element_order
      end
    end

    skip "builds a well-formed, signed and encrypted SAML Assertion" do
      pending("The crypto library uses a new IV each run making golden file tests useless. Find another way to verify.")
      Timecop.travel(Time.zone.local(2010, 6, 1, 13, 0, 0)) do
        expect(subject.build_encrypted_assertion).to be_equivalent_to(Nokogiri::XML(fixture('assertion-encrypted.xml'))).respecting_element_order
      end
    end

    it "builds a well-formed, signed, but unencrypted SAML Assertion" do
      Timecop.travel(Time.zone.local(2010, 6, 1, 13, 0, 0)) do
        signed_assertion = subject.build_signed_assertion
        expect(signed_assertion).to pass_validation(
          fixture_path('schemas/saml-schema-assertion-2.0.xsd'))
        golden = Nokogiri::XML(fixture('assertion-signed.xml'))

        def get_signature_node(my_doc)
          nodeset = my_doc.xpath(
            '//saml:Assertion/ds:Signature/ds:SignatureValue',
            saml:  Saml::XML::Namespaces::ASSERTION,
            ds: Saml::XML::Namespaces::SIGNATURE)
          expect(nodeset.length).to equal(1)
          nodeset.first
        end

        def get_signature(my_doc)
          get_signature_node(my_doc).content.gsub(/\s+/, "")
        end

        def get_certificate_node(my_doc)
          nodeset = my_doc.xpath(
            '//saml:Assertion/ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate',
            saml:  Saml::XML::Namespaces::ASSERTION,
            ds: Saml::XML::Namespaces::SIGNATURE)
          expect(nodeset.length).to equal(1)
          nodeset.first
        end

        def get_certificate(my_doc)
          get_certificate_node(my_doc).content.gsub(/\s+/, "")
        end

        expect(get_signature(signed_assertion)).to eq(get_signature(golden))
        expect(get_certificate(signed_assertion)).to eq(get_certificate(golden))

        # Remove the signature node before comparing the rest of the document.
        get_signature_node(signed_assertion).remove
        get_signature_node(golden).remove
        get_certificate_node(signed_assertion).remove
        get_certificate_node(golden).remove

        # TODO(awong): Have to remove the DTD from the assertion builder.
        #expect(signed_assertion).to be_equivalent_to(golden).respecting_element_order
      end
    end
  end
end
