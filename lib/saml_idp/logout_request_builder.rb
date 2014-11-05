require 'nokogiri'

# TODO(awong): Use the Onelogin version once that is stable.
module SamlIdp
  class LogoutRequestBuilder
    def initialize(response_id, issuer_uri, saml_slo_url, name_id, name_qualifier, session_index, signature_opts)
      @response_id = response_id
      @issuer_uri = issuer_uri
      @saml_slo_url = saml_slo_url
      @name_id = name_id
      @name_qualifier = name_qualifier
      @session_index = session_index
      @signature_opts = signature_opts
    end

    def build
      logout_request_builder = Nokogiri::XML::Builder.new do |xml|
        xml.LogoutRequest(xmlns: Saml::XML::Namespaces::PROTOCOL,
                          ID: @response_id,
                          Version: "2.0",
                          IssueInstant: now_iso,
                          Destination: @saml_slo_url) do
          xml.Issuer @issuer_uri, xmlns: Saml::XML::Namespaces::ASSERTION
          xml.NameID @name_id, xmlns: Saml::XML::Namespaces::ASSERTION,
            Format: Saml::XML::Namespaces::Formats::NameId::PERSISTENT,
            NameQualifier: @name_qualifier
          xml.SessionIndex @session_index
        end
      end

      SamlIdp::sign_root_element(
        logout_request_builder.doc,
        @signature_opts,
        '/samlp:LogoutRequest/saml:Issuer',
       { samlp: Saml::XML::Namespaces::PROTOCOL,
         saml: Saml::XML::Namespaces::ASSERTION })
    end

  private
    def now_iso
      Time.now.utc.iso8601
    end

  end
end

