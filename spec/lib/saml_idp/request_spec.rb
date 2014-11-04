require 'spec_helper'
require 'saml_idp/logout_request_builder'

module SamlIdp
  describe Request do
    context "AuthnRequest" do
      let(:raw_authn_request) { "<samlp:AuthnRequest Destination='http://localhost:1337/saml/auth' ID='_af43d1a0-e111-0130-661a-3c0754403fdb' IssueInstant='2013-08-06T22:01:35Z' Version='2.0' xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol'><saml:Issuer xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion'>localhost:3000</saml:Issuer><samlp:NameIDPolicy AllowCreate='true' Format='urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress' xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol'/></samlp:AuthnRequest>" }
      subject { described_class.new raw_authn_request }

      it "has a valid request_id" do
        subject.request_id.should == "_af43d1a0-e111-0130-661a-3c0754403fdb"
      end

      it "has a valid response_url" do
        subject.response_url.should == "http://localhost:3000/saml/consume"
      end

      it "has a valid service_provider" do
        subject.service_provider.should be_a ServiceProvider
      end

      it "has a valid service_provider" do
        subject.service_provider.should be_truthy
      end

      it "has a valid issuer" do
        subject.issuer.should == "localhost:3000"
      end

      it "has a valid valid_signature" do
        subject.valid_signature?.should be_truthy
      end
    end

    context "LogoutRequest" do
      let(:signature_opts) do
        {
          cert: SamlIdp::Default::SERVICE_PROVIDER_CERT,
          key: SamlIdp::Default::SERVICE_PROVIDER_KEY,
          signature_alg: 'rsa-sha256',
          digest_alg: 'sha256'
        }
      end
      subject { described_class.new(
        LogoutRequestBuilder.new(
          '_response_id',
          'localhost:3000',
          'http://localhost:1337/saml/logout',
          'himom',
          'some_qualifier',
          'abc123index',
          signature_opts).build.to_xml) }

      it "has a valid request_id" do
        subject.request_id.should == "_response_id"
      end

      it "has a valid response_url" do
        subject.response_url.should == "http://localhost:3000/saml/sso_return"
      end

      it "has a valid service_provider" do
        subject.service_provider.should be_a ServiceProvider
      end

      it "has a valid service_provider" do
        subject.service_provider.should be_truthy
      end

      it "has a valid issuer" do
        subject.issuer.should == "localhost:3000"
      end

      it "requires a valid_signature" do
        # Signed docoument should be valid.
        subject.valid_signature?.should be_truthy

        # Tampered document should fail validation.
        tampered_document = described_class.new subject.document.root.to_xml
        tampered_document.document.root.add_child(Nokogiri::XML("<tamper />").root)
        tampered_document.valid_signature?.should be_falsey

        # Signatureless document should fail validation.
        subject.document.xpath('/*/ds:Signature', 
                               ds: Saml::XML::Namespaces::SIGNATURE)[0].remove
        subject.valid_signature?.should be_falsey
      end
    end

  end
end
