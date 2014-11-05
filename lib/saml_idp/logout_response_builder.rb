require 'nokogiri'

module SamlIdp
  class LogoutResponseBuilder

    def initialize(response_id, issuer_uri, saml_slo_url, saml_request_id, signature_opts)
      @response_id = response_id
      @issuer_uri = issuer_uri
      @saml_slo_url = saml_slo_url
      @saml_request_id = saml_request_id
      @signature_opts = signature_opts
    end

    def build
      builder = Nokogiri::XML::Builder.new do |xml|
        xml.LogoutResponse(xmlns: Saml::XML::Namespaces::PROTOCOL,
                           ID: response_id_string,
                           Version: "2.0",
                           IssueInstant: now_iso,
                           Destination: @saml_slo_url,
                           InResponseTo: @saml_request_id) do
          xml.Issuer @issuer_uri, xmlns: Saml::XML::Namespaces::ASSERTION
          xml.Status do
            xml.StatusCode Value: Saml::XML::Namespaces::Statuses::SUCCESS 
          end
        end
      end
      SamlIdp::sign_root_element(
        builder.doc,
        @signature_opts,
        '/*/saml:Issuer',
        { saml: Saml::XML::Namespaces::ASSERTION })
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
