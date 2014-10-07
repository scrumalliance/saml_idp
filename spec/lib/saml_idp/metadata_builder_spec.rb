require 'spec_helper'
module SamlIdp
  describe MetadataBuilder do
    it "builds a valid signed metadata" do
      metadata = subject.build
      expect(metadata).to pass_validation(
        fixture_path('schemas/saml-schema-metadata-2.0.xsd'))

      expect(Saml::XML::Document.parse(metadata.to_xml).valid_signature?(Default::FINGERPRINT)).to be_truthy
    end

    it "has expected fields" do
      # Rip the assertion into a separate doc for more stabe comparisons.
      expect(subject.build).to be_equivalent_to(fixture('metadata.xml')).respecting_element_order
    end
  end
end
