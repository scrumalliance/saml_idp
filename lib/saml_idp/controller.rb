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

    def initialize
      self.signature_opts = {
        cert: SamlIdp.config.x509_certificate,
        key: SamlIdp.config.secret_key,
        signature_alg: SamlIdp.config.signature_alg,
        digest_alg: SamlIdp.config.digest_alg,
      }
    end

    attr_accessor :signature_opts
    attr_accessor :saml_request

    protected

    def validate_saml_request(raw_saml_request = params[:SAMLRequest])
      if raw_saml_request.nil?
        render nothing: true, status: :forbidden
        return
      end
      decode_request(raw_saml_request)
      if SamlIdp.config.verify_authnrequest_sig
        raise "AuthnRequest signature verification enfored. Must have cert." if service_provider[:cert].nil?

      binding.pry
        raw_params = request.query_string.split('&')
        saml_request_param = raw_params.select { |x| x =~ /^SAMLRequest=/ }[0]
        algorithm_param = raw_params.select { |x| x =~ /^SigAlg=/ }[0]
        relay_state_param = raw_params.select { |x| x =~ /^RelayState=/ }[0]
        signature = raw_params.select { |x| x =~ /^Signature=/ }[0]

        # TODO(awong): Return SAML Error here. Don't raise.
        raise "Missing part of signature" unless !algorithm_param.nil? && !saml_request_param.nil? && !signature.nil?

        # TODO(awong): Get the raw parameters here. This is silly to reconstruct and
        # somewhat unsafe.
        if relay_state.nil?
          plain_string = "#{saml_request_param}&#{algorithm_param}"
        else
          plain_string = "#{saml_request_param}&#{relay_state_param}&#{algorithm_param}"
        end

        case URI.decode_www_form_component(algorithm_param.split('=')[1])
        when 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
          digest = OpenSSL::Digest::SHA1.new
        when 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
          digest = OpenSSL::Digest::SHA256.new
        when 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512'
          digest = OpenSSL::Digest::SHA512.new
        else
          raise "Unknown sig algorithm: #{URI.decode_www_form_component(algorithm_param.split('=')[1])}"
        end
        service_provider_cert = OpenSSL::X509::Certificate.new(service_provider[:cert])
        if !service_provider_cert.public_key.verify(digest, Base64.decode64(signature), plain_string)
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

      encryption_opts = {}
      if not service_provider[:block_encryption].nil?
        encryption_opts = {
          cert: service_provider[:cert],
          block_encryption: service_provider[:block_encryption],
          key_transport: service_provider[:key_transport],
        }
        raise "Invalid encryption config for #{saml_request.issuer}" if encryption_opts[:cert].nil? || encryption_opts[:block_encryption].nil? || encryption_opts[:key_transport].nil?
      end

      response_doc = SamlResponse.new(
        reference_id,
        response_id,
        opt_issuer_uri,
        principal,
        audience_uri,
        saml_request_id,
        saml_acs_url,
        signature_opts,
        encryption_opts,
        authn_context_classref
      ).build

      Base64.encode64(response_doc.to_xml)
    end

    def relay_state
      params.has_key?(:RelayState) ? params[:RelayState] : nil
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
