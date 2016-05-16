require 'spec_helper'
module SamlIdp
  describe MetadataBuilder do
    it "builds a valid signed metadata" do
      metadata = subject.build
      expect(metadata).to pass_validation(
        fixture_path('schemas/saml-schema-metadata-2.0.xsd'))

      # TODO(awong): Make sure all golden test files are signed with the same cert/key pair.
      expect(Saml::XML::Document.parse(metadata.to_xml).valid_signature?(
        SamlIdp::Default::IDP_FINGERPRINT)).to be_truthy
    end

    it "has expected fields" do
      SamlIdp.config.base_saml_location = nil
      # Rip the assertion into a separate doc for more stabe comparisons.
      generated_doc = subject.build
      expected_doc = Nokogiri::XML(fixture("metadata.xml"))

      # Signature node just gets in the way of checking fields. Remove it.
      signature_node = generated_doc.xpath('/*/ds:Signature', ds: Saml::XML::Namespaces::SIGNATURE)[0]
      expect(signature_node.present?).to be_truthy
      signature_node.remove

      expect(generated_doc).to be_equivalent_to(expected_doc).respecting_element_order
    end
  end
end
