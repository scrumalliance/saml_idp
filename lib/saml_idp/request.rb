require 'saml_idp/service_provider'
module SamlIdp
  class Request
    def self.from_deflated_request(raw)
      if raw
        decoded = Base64.decode64(raw)
        zstream = Zlib::Inflate.new(-Zlib::MAX_WBITS)
        begin
          inflated = zstream.inflate(decoded).tap do
            zstream.finish
            zstream.close
          end
        rescue Zlib::DataError # not compressed
          inflated = decoded
        end
      else
        inflated = ""
      end
      new(inflated)
    end

    attr_accessor :raw_xml

    delegate :config, to: :SamlIdp
    private :config
    delegate :xpath, to: :document
    private :xpath

    def initialize(raw_xml = "")
      self.raw_xml = raw_xml
    end

    def request_id
      return authn_request["ID"] if authn_request.present?
      return logout_request["ID"] if logout_request.present?
      nil
    end

    def response_url
      return service_provider.acs_url if xpath("//samlp:AuthnRequest", samlp: samlp).first.present?
      return service_provider.sso_url if xpath("//samlp:LogoutRequest", samlp: samlp).first.present?
      return nil
    end

    def valid?
      # TODO(awong): This should validate against the schema. Also assert the
      # existance of only 1 AuthnRequest or LogoutRequest. This is probably
      # handled by schema.
      service_provider? &&
        (authn_request.present? ^ logout_request.present?) &&
        valid_signature? &&
        response_url.present?
    end

    def valid_signature?
      # Force signatures for logout requests because there is no other
      # protection against a cross-site DoS.
      service_provider.valid_signature?(document, logout_request.present?)
    end

    def service_provider?
      service_provider.valid?
    end

    def service_provider
      @service_provider ||= ServiceProvider.new((service_provider_finder[issuer] || {}).merge(identifier: issuer))
    end

    def issuer
      @content ||= xpath("//saml:Issuer", saml: assertion).first.try(:content)
      @content if @content.present?
    end

    def document
      @document ||= Saml::XML::Document.parse(raw_xml)
    end

    def authn_request
      @authn_request ||= xpath("//samlp:AuthnRequest", samlp: samlp).first
    end

    def logout_request
      @logout_request ||= xpath("//samlp:LogoutRequest", samlp: samlp).first
    end

    def samlp
      Saml::XML::Namespaces::PROTOCOL
    end
    private :samlp

    def assertion
      Saml::XML::Namespaces::ASSERTION
    end
    private :assertion

    def signature_namespace
      Saml::XML::Namespaces::SIGNATURE
    end
    private :signature_namespace

    def service_provider_finder
      config.service_provider.finder
    end
    private :service_provider_finder
  end
end
