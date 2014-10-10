require 'spec_helper'

module SamlIdp
  describe ResponseBuilder do

    it "builds a well-formed saml response for an unencrypted" do
      Timecop.travel(Time.zone.local(2010, 6, 1, 13, 0, 0)) do
        response_builder = ResponseBuilder.new(
          "response_id",
          "http://example.com",
          "http://sportngin.com",
          "_134",
          Nokogiri::XML(fixture('assertion-simple.xml')))
        response = response_builder.build
        expect(response).to pass_validation(
          fixture_path('schemas/saml-schema-protocol-2.0.xsd'))

        # Rip the assertion into a separate doc for more stabe comparisons.
        response_assertion = Nokogiri::XML('')
        response_assertion.add_child(response.xpath(
            '//saml:Assertion',
            saml:  Saml::XML::Namespaces::ASSERTION,
            ds: Saml::XML::Namespaces::SIGNATURE)[0])
        expect(response_assertion).to be_equivalent_to(
          fixture('assertion-simple.xml')).respecting_element_order
        expect(response).to be_equivalent_to(
          fixture('response-assertion-removed.xml')).respecting_element_order
      end
    end

    it "builds a well-formed saml response for an encrypted assertion" do
      Timecop.travel(Time.zone.local(2010, 6, 1, 13, 0, 0)) do
        response_builder = ResponseBuilder.new(
          "response_id",
          "http://example.com",
          "http://sportngin.com",
          "_134",
          Nokogiri::XML(fixture('assertion-encrypted.xml')))
        response = response_builder.build
        expect(response).to pass_validation(
          fixture_path('schemas/saml-schema-protocol-2.0.xsd'))

        # Rip the assertion into a separate doc for more stabe comparisons.
        response_assertion = Nokogiri::XML('')
        response_assertion.add_child(response.xpath(
            '//saml:EncryptedAssertion',
            saml:  Saml::XML::Namespaces::ASSERTION,
            ds: Saml::XML::Namespaces::SIGNATURE)[0])

        expect(response_assertion).to be_equivalent_to(
          fixture('assertion-encrypted.xml')).respecting_element_order
        expect(response).to be_equivalent_to(
          fixture('response-assertion-removed.xml')).respecting_element_order
      end
    end
  end
end
