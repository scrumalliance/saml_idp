require 'nokogiri'

module SamlIdp
  class AssertionBuilder
    delegate :config, to: :SamlIdp

    def initialize(reference_id, issuer_uri, principal, audience_uri,
                   saml_request_id, saml_acs_url, signing_algorihm_UNUSED,
                   authn_context_classref, sp_cert)
      @reference_id = reference_id
      @issuer_uri = issuer_uri
      @principal = principal
      @audience_uri = audience_uri
      @saml_request_id = saml_request_id
      @saml_acs_url = saml_acs_url
      @signing_algorihm_UNUSED = signing_algorihm_UNUSED
      @authn_context_classref = authn_context_classref
      @sp_cert = sp_cert
    end

    # Build a samlp:Assertion per section #2.3.3.
    #
    # Required attributes:
    #   ID: xs:ID string following #1.3.4 uniqueness requirements.
    #   IssueInstant: Time instant of issuance in UTC following #1.3.3.
    #   Version: "2.0" for Saml 2.0. #2.3.3
    #
    # Required elements:
    #   Issuer: SAML Authority making the assertion. #2.2.5
    #
    # Optional elements that Service Providers should consier required #2.3.3:
    #   ds:Signature: XMLSig for the Assertion node. Prevents forgery.
    #                 Recipient must validate against known cert to verify
    #                 integrity and authentication. Particularly important
    #                 if compatibility still forces use of xmlenc 1.0 with
    #                 CBC block ciphers. It doesn't fix the issue, but it
    #                 makes it harder to break.
    #
    # Optional single elements (#2.3.3):
    #   Subject: The subject of all elements the assertion. Must exist if no
    #            Statement element exists. #2.4
    #   Conditions: Restricts validity of assertion. See #2.5
    #   Advice: Additional information about the assertion.
    #
    # Optional 0 or more elements (#2.3.3):
    #   Statement: Used by extension schemas.
    #   AuthnStatement: An authentication statement.
    #   AuthzDecisionStatement: An authorization decision statement.
    #   AttributeStatement: An attribute statement.
    #
    # The assertion elements also must be in sequence (#2.3.3). Here is
    # a copy of the XML schema.
    #   <element name="Assertion" type="saml:AssertionType"/>
    #   <complexType name="AssertionType">
    #     <sequence>
    #     <element ref="saml:Issuer"/>
    #     <element ref="ds:Signature" minOccurs="0"/>
    #     <element ref="saml:Subject" minOccurs="0"/>
    #     <element ref="saml:Conditions" minOccurs="0"/>
    #     <element ref="saml:Advice" minOccurs="0"/>
    #     <choice minOccurs="0" maxOccurs="unbounded">
    #        <element ref="saml:Statement"/>
    #        <element ref="saml:AuthnStatement"/>
    #        <element ref="saml:AuthzDecisionStatement"/>
    #        <element ref="saml:AttributeStatement"/>
    #     </choice>
    #   </sequence>
    #     <attribute name="Version" type="string" use="required"/>
    #     <attribute name="ID" type="ID" use="required"/>
    #     <attribute name="IssueInstant" type="dateTime" use="required"/>
    #   </complexType>
    def build_assertion
      builder = Nokogiri::XML::Builder.new do |xml|
        xml.Assertion xmlns: Saml::XML::Namespaces::ASSERTION,
          ID: reference_string,
          IssueInstant: now_iso,
          Version: "2.0" do

          # Add Issuer element per #2.2.5
          xml.Issuer @issuer_uri

          # TODO(awong): Fix nokogiri-xmlsec to understand signature template
          # nodes and add one here rather than rearranging order below.

          # Add Subject element per #2.4
          #
          # <BaseID>, <NameID>, or <EncryptedID> [Optional]: 
          #    Identifies the entity expected to satisfy the enclosing subject
          #
          # <SubjectConfirmationData> [Optional]:
          #    Additional confirmation information to be used by a specific
          #    confirmation method such as ds:KeyInfo.
          xml.Subject do
            xml.NameID name_id, Format: name_id_format[:name]
            xml.SubjectConfirmation Method: Saml::XML::Namespaces::Methods::BEARER do
              xml.SubjectConfirmationData(InResponseTo: @saml_request_id,
                                          NotOnOrAfter: not_on_or_after_subject,
                                          Recipient: @saml_acs_url) do
              end
            end
          end

          # Conditions #2.5
          xml.Conditions NotBefore: not_before, NotOnOrAfter: not_on_or_after_condition do
            xml.AudienceRestriction do
              xml.Audience @audience_uri
            end
          end

          # AuthnStatment #2.7.2
          xml.AuthnStatement AuthnInstant: now_iso, SessionIndex: reference_string do
            xml.AuthnContext do |context|
              xml.AuthnContextClassRef @authn_context_classref
            end
          end

          # Attribute Statements #2.7.3
          xml.parent.add_child(build_attribute_statement.root)
        end
      end
      builder.doc
    end

    def build_signed_assertion
      doc = build_assertion
      # Hack to add the ASSERTION_ID_DOCTYPE to the document. XMLSec is strict
      # with its validtion of the Reference URI and requires that the URI
      # be a valid intradoc id if using a #.
      doc = Nokogiri::XML(ASSERTION_ID_DOCTYPE + doc.root.to_xml)
      # The refernece string should be the ID of the <Assertion> block.
      # TODO(awong): Use an xpath to find that rather than rereading reference_string.
      doc.sign! certificate: config.x509_certificate, key: config.secret_key, uri: "##{reference_string}"
      issuer = doc.xpath('//saml:Assertion/saml:Issuer',
                         'saml' => Saml::XML::Namespaces::ASSERTION)[0]
      signature = doc.xpath('//saml:Assertion/ds:Signature',
                            'saml' => Saml::XML::Namespaces::ASSERTION,
                            'ds' => Saml::XML::Namespaces::SIGNATURE)[0]
      issuer.add_next_sibling(signature)
      doc
    end

    def build_encrypted_assertion
      doc = build_signed_assertion
      doc.encrypt! key: @sp_cert.public_key.to_pem
      # Create an EncryptionAssertion (#2.3.4)
      encrypted_assertion_builder = Nokogiri::XML::Builder.new do |xml|
        xml.EncryptedAssertion xmlns: Saml::XML::Namespaces::ASSERTION do
          xml.parent.add_child(doc.root)
        end
      end
      encrypted_assertion_builder.doc
    end

  private
    # Builds an Attribute Statements #2.7.3
    def build_attribute_statement
      builder = Nokogiri::XML::Builder.new do |xml|
        xml.AttributeStatement do
          config.attributes.each do |friendly_name, attrs|
            attrs = (attrs || {}).with_indifferent_access
            xml.Attribute(Name: attrs[:name] || friendly_name,
                          NameFormat: attrs[:name_format] || Saml::XML::Namespaces::Formats::Attr::URI,
                          FriendlyName: friendly_name.to_s) do
              values = get_values_for friendly_name, attrs[:getter]
              values.each do |val|
                xml.AttributeValue val.to_s
              end
            end
          end
        end
      end
      builder.doc
    end

    def get_values_for(friendly_name, getter)
      result = nil
      if getter.present?
        if getter.respond_to?(:call)
          result = getter.call(@principal)
        else
          message = getter.to_s.underscore
          result = @principal.public_send(message) if @principal.respond_to?(message)
        end
      elsif getter.nil?
        message = friendly_name.to_s.underscore
        result = @principal.public_send(message) if @principal.respond_to?(message)
      end
      Array(result)
    end

    def name_id
      name_id_getter.call @principal
    end

    def name_id_getter
      getter = name_id_format[:getter]
      if getter.respond_to? :call
        getter
      else
        # TODO(awong): What is this doing?
        ->(principal) { principal.public_send getter.to_s }
      end
    end

    def name_id_format
      @name_id_format ||= NameIdFormatter.new(config.name_id.formats).chosen
    end

    def reference_string
      "_#{@reference_id}"
    end

    def now
      @now ||= Time.now.utc
    end

    # TODO(awong): Validity duration should be configurable.
    def now_iso
      iso { now }
    end

    def not_before
      iso { now - 5 }
    end

    def not_on_or_after_condition
      iso { now + 60 * 60 }
    end

    def not_on_or_after_subject
      iso { now + 3 * 60 }
    end

    def iso
      yield.iso8601
    end

    ASSERTION_ID_DOCTYPE = <<DOCTYPE
<!DOCTYPE Assertion [
  <!ELEMENT Assertion (#PCDATA)>
  <!ATTLIST Assertion ID ID #IMPLIED>
]>
DOCTYPE
  end
end
