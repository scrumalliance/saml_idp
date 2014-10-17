# encoding: utf-8
require 'spec_helper'

describe SamlIdp::Controller do
  include SamlIdp::Controller

  XMLDSIG_RSA_SHA256_URI = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
  XMLENC_SHA256_URI = 'http://www.w3.org/2001/04/xmlenc#sha256'

  def render(*)
  end

  def params
    @params ||= {}
  end

  it "should find the SAML ACS URL" do
    requested_saml_acs_url = "https://example.com/saml/consume"
    params[:SAMLRequest] = make_saml_request(requested_saml_acs_url)
    validate_saml_request
    saml_acs_url.should == requested_saml_acs_url
  end

  context "SAML Responses" do
    before(:each) do
      params[:SAMLRequest] = make_saml_request
      validate_saml_request
    end

    let(:principal) { double email_address: "foo@example.com" }

    skip "should create an unsigned, unencrypted SAML Response" do
    end

    skip "should create a signed SAML Response" do
    end

    it "should create an Encrypted, signed SAML Response" do
      self.signature_opts[:signature_alg] = 'rsa-sha256'
      self.signature_opts[:digest_method] = 'sha256'
      saml_response = encode_response(principal)
      response = OneLogin::RubySaml::Response.new(
        saml_response,
        { private_key: SamlIdp::Default::SERVICE_PROVIDER_KEY })
      response.name_id.should == "foo@example.com"
      response.issuer.should == "http://example.com"
      response.settings = saml_settings
      response.is_valid?.should be_truthy
      nokogiri_doc = Nokogiri::XML(response.document.to_s)
      signature_method_nodeset = nokogiri_doc.xpath(
        '//samlp:Response/saml:Assertion/ds:Signature/ds:SignedInfo/ds:SignatureMethod',
        samlp: Saml::XML::Namespaces::PROTOCOL,
        saml: Saml::XML::Namespaces::ASSERTION,
        ds: Saml::XML::Namespaces::SIGNATURE)
      expect(signature_method_nodeset.length).to be(1)
      expect(signature_method_nodeset[0].attribute('Algorithm').value).to eql(XMLDSIG_RSA_SHA256_URI)

      digest_method_nodeset = nokogiri_doc.xpath(
        '//samlp:Response/saml:Assertion/ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestMethod',
        samlp: Saml::XML::Namespaces::PROTOCOL,
        saml: Saml::XML::Namespaces::ASSERTION,
        ds: Saml::XML::Namespaces::SIGNATURE)
      expect(digest_method_nodeset.length).to be(1)
      expect(digest_method_nodeset[0].attribute('Algorithm').value).to eql(XMLENC_SHA256_URI)
    end

    ['rsa-sha1', 'rsa-sha256', 'rsa-sha384', 'rsa-sha512'].each do |algorithm_name|
      skip "should create a SAML Response using the #{algorithm_name} algorithm" do
        signature_alg = algorithm_name
        digest_alg = algorithm_name.split('-')[1]
        self.signature_opts[:signature_alg] = signature_alg
        self.signature_opts[:digest_alg] = digest_alg
        saml_response = encode_response(principal)
        response = OneLogin::RubySaml::Response.new(
          saml_response,
          { private_key: SamlIdp::Default::SERVICE_PROVIDER_KEY })
        response.name_id.should == "foo@example.com"
        response.issuer.should == "http://example.com"
        response.settings = saml_settings
        response.is_valid?.should be_truthy

        nokogiri_doc = Nokogiri::XML(response.document.to_s)
        signature_method_nodeset = nokogiri_doc.xpath(
        '//samlp:Response/saml:Assertion/ds:Signature/ds:SignedInfo/ds:SignatureMethod',
        samlp: Saml::XML::Namespaces::PROTOCOL,
        saml: Saml::XML::Namespaces::ASSERTION,
        ds: Saml::XML::Namespaces::SIGNATURE)
      expect(signature_method_nodeset.length).to be(1)
      expect(signature_method_nodeset[0].attribute('Algorithm').value.split('#')[-1]).to eql(signature_alg)

      digest_method_nodeset = nokogiri_doc.xpath(
        '//samlp:Response/saml:Assertion/ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestMethod',
        samlp: Saml::XML::Namespaces::PROTOCOL,
        saml: Saml::XML::Namespaces::ASSERTION,
        ds: Saml::XML::Namespaces::SIGNATURE)
      expect(digest_method_nodeset.length).to be(1)
      expect(digest_method_nodeset[0].attribute('Algorithm').value.split('#')[-1]).to eql(digest_alg)
      end
    end
  end

end
