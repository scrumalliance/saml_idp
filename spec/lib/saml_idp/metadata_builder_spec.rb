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
      # Rip the assertion into a separate doc for more stabe comparisons.
      expect(subject.build).to be_equivalent_to(fixture('metadata.xml')).respecting_element_order
    end
  end
end
