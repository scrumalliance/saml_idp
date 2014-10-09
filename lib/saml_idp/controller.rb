require 'openssl'
require 'base64'
require 'time'
require 'uuid'
require 'saml_idp/request'

module SamlIdp
  module Controller
    extend ActiveSupport::Concern

    included do
      helper_method :saml_acs_url if respond_to? :helper_method
    end

    attr_accessor :algorithm
    attr_accessor :saml_request

    protected

    def validate_saml_request(raw_saml_request = params[:SAMLRequest])
      decode_request(raw_saml_request)
      algorithm = params[:SigAlg]
      signature = params[:Signature]
      if !signature.nil? || !algorithm.nil?
        raise "Missing part of signature" unless !signature.nil? && !algorithm.nil?
        # TODO(awong): Get the raw parameters here. This is silly to reconstruct and
        # somewhat unsafe.
        plain_string = "SAMLRequest=#{URI.encode_www_form_component(raw_saml_request)}&SigAlg=#{URI.encode_www_form_component(algorithm)}"
        case algorithm
        when 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
          digest = OpenSSL::Digest::SHA1.new
        when 'http://www.w3.org/2001/04/xmlenc#sha256'
          digest = OpenSSL::Digest::SHA256.new
        when 'http://www.w3.org/2001/04/xmlenc#sha512'
          digest = OpenSSL::Digest::SHA512.new
        end
        service_provider_cert = OpenSSL::X509::Certificate.new(service_provider[:cert])
        if !service_provider_cert.public_key.verify(digest, Base64.urlsafe_decode64(signature), plain_string)
          logger.error("Bad signature on get request")
          render nothing: true, status: :forbidden
          return
        end
      end
      render nothing: true, status: :forbidden unless valid_saml_request?
    end

    def decode_request(raw_saml_request)
      self.saml_request = Request.from_deflated_request(raw_saml_request)
    end

    def encode_response(principal, opts = {})
      response_id, reference_id = get_saml_response_id, get_saml_reference_id
      audience_uri = opts[:audience_uri] || saml_request.issuer || saml_acs_url[/^(.*?\/\/.*?\/)/, 1]
      opt_issuer_uri = opts[:issuer_uri] || issuer_uri
      authn_context_classref = opts[:authn_context_classref] || Saml::XML::Namespaces::AuthnContext::ClassRef::PASSWORD
      service_provider_cert = service_provider[:cert]
      if service_provider[:encrypted_assertions] && service_provider_cert.nil?
        raise "Must have cert"
      end

      response_doc = SamlResponse.new(
        reference_id,
        response_id,
        opt_issuer_uri,
        principal,
        audience_uri,
        saml_request_id,
        saml_acs_url,
        algorithm,
        authn_context_classref,
        service_provider_cert
      ).build

      Base64.encode64(response_doc.to_xml)
    end

    def issuer_uri
      (SamlIdp.config.base_saml_location.present? && SamlIdp.config.base_saml_location) ||
        (defined?(request) && request.url.to_s.split("?").first) ||
        "http://example.com"
    end

    def valid_saml_request?
      saml_request.valid?
    end

    def saml_request_id
      saml_request.request_id
    end

    def saml_acs_url
      saml_request.acs_url
    end

    def get_saml_response_id
      UUID.generate
    end

    def get_saml_reference_id
      UUID.generate
    end

    def service_provider
      SamlIdp.config.service_provider.finder.(saml_request.issuer)
    end
  end
end
