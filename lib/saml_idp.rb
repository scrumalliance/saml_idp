# encoding: utf-8
module SamlIdp
  require 'active_support/all'
  require 'saml_idp/saml_response'
  require 'saml_idp/configurator'
  require 'saml_idp/controller'
  require 'saml_idp/default'
  require 'saml_idp/metadata_builder'
  require 'saml_idp/version'
  require 'saml_idp/engine' if defined?(::Rails) && Rails::VERSION::MAJOR > 2

  def self.config
    @config ||= SamlIdp::Configurator.new
  end

  def self.configure
    yield config
  end

  def self.metadata
    @metadata ||= MetadataBuilder.new(config)
  end

  def self.add_id_doctype(doc, tag_to_sign)
    dtd = "<!DOCTYPE #{tag_to_sign} [ <!ELEMENT #{tag_to_sign} (#PCDATA)> <!ATTLIST #{tag_to_sign} ID ID #IMPLIED> ]>"
    Nokogiri::XML(dtd + doc.root.to_xml)
  end

  def self.sign_root_element(doc, signature_opts, path_to_prev_sibling_of_signature = nil, namespaces = nil)
    # xmldsig expects the tag being signed has an id field that it can reference.
    tag_to_sign = doc.first_element_child.name
    doc = add_id_doctype(doc, tag_to_sign)
    cloned_signature_opts = signature_opts.clone
    cloned_signature_opts[:uri] = "##{doc.first_element_child[:ID]}"
    doc.sign! cloned_signature_opts
    if path_to_prev_sibling_of_signature
      signature = doc.xpath('/*/ds:Signature', 'ds' => Saml::XML::Namespaces::SIGNATURE)[0]
      prev_node = doc.xpath(path_to_prev_sibling_of_signature, namespaces)[0]
      prev_node.add_next_sibling(signature)
    end

    no_dtd = Nokogiri::XML('<dummy />')
    no_dtd.root.replace(doc.root)
    no_dtd
  end
end

# TODO Needs extraction out
module Saml
  module XML
    module Namespaces
      METADATA = "urn:oasis:names:tc:SAML:2.0:metadata"
      ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
      SIGNATURE = "http://www.w3.org/2000/09/xmldsig#"
      PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol"

      module Statuses
        SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
      end

      module Consents
        UNSPECIFIED = "urn:oasis:names:tc:SAML:2.0:consent:unspecified"
      end

      module AuthnContext
        module ClassRef
          PASSWORD = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"
          PASSWORD_PROTECTED = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
        end
      end

      module Methods
        BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
      end

      module Formats
        module Attr
          URI = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
        end

        module NameId
          EMAIL_ADDRESS = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
          TRANSIENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
          PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
        end
      end
    end

    class Document < Nokogiri::XML::Document
      ValidationError = Class.new(StandardError)

      def signed?
        !!signature_node
      end

      def valid_signature?(fingerprint_or_cert)
        # Null signature is tautologically valid.
        #
        # TODO(awong): Should default to requiring a signature node.
        return true if not signed?

        # TODO(awong): If this is a cert,there's no point in fingerprinting. Just compare
        # the two directly and save the CPU.
        if fingerprint_or_cert.include?('-----BEGIN CERTIFICATE-----')
          fingerprint = SamlIdp::fingerprint_cert(fingerprint_or_cert)
        else
          fingerprint = fingerprint_or_cert
        end

        signature = signature_node
        cert_element = signature.at_xpath("./ds:KeyInfo/ds:X509Data/ds:X509Certificate", ds: Namespaces::SIGNATURE)
        raise ValidationError.new("Certificate element missing in response (ds:X509Certificate)") unless cert_element
        base64_cert  = cert_element.text
        cert_text    = Base64.decode64(base64_cert)
        cert         = OpenSSL::X509::Certificate.new(cert_text)

        # Normalize fingerprint and guess at digest method based on length.
        normalized_fingerprint = fingerprint.gsub(/[^a-zA-Z0-9]/,"").downcase
        case normalized_fingerprint.length
        when 64
          fingerprint_method = Digest::SHA256
        when 40
          fingerprint_method = Digest::SHA1
        else
          raise ValidationError("Unexpected Certificate fingerprint length: #{normalized_fingerprint}")
        end

        cert_fingerprint = fingerprint_method.hexdigest(cert.to_der)
        if cert_fingerprint != normalized_fingerprint
          return false
        end

        id_element = at_xpath('//*[@ID]')
        doc_with_dtd = SamlIdp::add_id_doctype(self, id_element.name)
        doc_with_dtd.verify_with(cert: cert.to_pem)
      end

      def signature_namespace
        Namespaces::SIGNATURE
      end

      def to_xml
        super(
          save_with: Nokogiri::XML::Node::SaveOptions::AS_XML | Nokogiri::XML::Node::SaveOptions::NO_DECLARATION
        ).strip
      end

    private
      def signature_node
        at_xpath("//ds:Signature", ds: Namespaces::SIGNATURE)
      end
    end
  end
end
