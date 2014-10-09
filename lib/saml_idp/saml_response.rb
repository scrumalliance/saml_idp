require 'openssl'
require 'saml_idp/assertion_builder'
require 'saml_idp/response_builder'

module SamlIdp
  # TODO(awong): This class is not worth its weight. Kill it with fire.
  class SamlResponse
    def initialize(reference_id,
                   response_id,
                   issuer_uri,
                   principal,
                   audience_uri,
                   saml_request_id,
                   saml_acs_url,
                   algorithm,
                   authn_context_classref,
                   sp_cert)
      @reference_id = reference_id
      @response_id = response_id
      @issuer_uri = issuer_uri
      @principal = principal
      @audience_uri = audience_uri
      @saml_request_id = saml_request_id
      @saml_acs_url = saml_acs_url
      @algorithm = algorithm
      @authn_context_classref = authn_context_classref
      @sp_cert = (sp_cert.nil? || sp_cert.empty?) ? nil : OpenSSL::X509::Certificate.new(sp_cert) 
    end

    def build
      @built ||= response_builder.build
    end

  private

    def response_builder
      if @sp_cert.nil?
        ResponseBuilder.new(@response_id, @issuer_uri, @saml_acs_url, @saml_request_id,
                            assertion_builder.build_signed_assertion)
      else
        ResponseBuilder.new(@response_id, @issuer_uri, @saml_acs_url, @saml_request_id,
                            assertion_builder.build_encrypted_assertion)
      end
    end

    def assertion_builder
      @assertion_builder ||= AssertionBuilder.new @reference_id,
        @issuer_uri,
        @principal,
        @audience_uri,
        @saml_request_id,
        @saml_acs_url,
        @algorithm,
        @authn_context_classref,
        @sp_cert
    end
  end
end
