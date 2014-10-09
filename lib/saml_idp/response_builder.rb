require 'nokogiri'

module SamlIdp
  class ResponseBuilder

    # Builds a SAML 2.0 response element per #3.3.3. 
    #
    # The response is always assumed to be successful.
    def initialize(response_id, issuer_uri, saml_acs_url, saml_request_id, assertion)
      @response_id = response_id
      @issuer_uri = issuer_uri
      @saml_acs_url = saml_acs_url
      @saml_request_id = saml_request_id
      @assertion = assertion
    end

    def build
      builder = Nokogiri::XML::Builder.new do |xml|
        xml.Response(xmlns: Saml::XML::Namespaces::PROTOCOL,
                     ID: response_id_string,
                     Version: "2.0",
                     IssueInstant: now_iso,
                     Destination: @saml_acs_url,
                     Consent: Saml::XML::Namespaces::Consents::UNSPECIFIED,
                     InResponseTo: @saml_request_id) do
          xml.Issuer @issuer_uri, xmlns: Saml::XML::Namespaces::ASSERTION
          xml.Status do
            xml.StatusCode Value: Saml::XML::Namespaces::Statuses::SUCCESS 
          end
          xml.parent.add_child @assertion.root
        end
      end
      builder.doc
    end

  private
    def response_id_string
      "_#{@response_id}"
    end

    def now_iso
      Time.now.utc.iso8601
    end

  end
end
