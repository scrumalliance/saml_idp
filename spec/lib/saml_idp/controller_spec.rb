# encoding: utf-8
require 'spec_helper'
require 'saml_idp/logout_request_builder'

SamlIdp.config.base_saml_location = 'http://example.com'

class MySamlController < ApplicationController
  include SamlIdp::Controller

  def test_saml_request
    validate_saml_request
    if self.saml_request
      #puts self.saml_request.raw_xml
      #puts self.saml_request.pretty_inspect
    end
    if valid_saml_request?
      render nothing: true, status: :ok
    end
  end

  def test_saml_response
    saml_response_url
  end

  def test_encode_response(payload)
    encode_response(payload)
  end

  def test_response_doc(payload)
    response_doc(payload)
  end
end

describe MySamlController, type: :controller do

  before do
    routes.draw {
      get 'test_saml_request' => 'my_saml#test_saml_request'
      post 'test_saml_request' => 'my_saml#test_saml_request'
    }
  end

  XMLDSIG_RSA_SHA256_URI = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
  XMLENC_SHA256_URI = 'http://www.w3.org/2001/04/xmlenc#sha256'

  it "should find the SAML ACS URL" do
    pending("Should this allow for non-metadata specified URLs?")
    requested_saml_acs_url = "https://example.com/saml/consume"
    saml_request = make_saml_request(requested_saml_acs_url)
    get :test_saml_request, { SAMLRequest: saml_request }
    expect(subject.test_saml_response).to eq(requested_saml_acs_url)
  end

  context "SAML Responses" do
    before(:each) do
      get :test_saml_request, { SAMLRequest: make_saml_request }
    end

    let(:principal) { double email_address: "foo@example.com" }

    skip "should create an unsigned, unencrypted SAML Response" do
    end

    skip "should create a signed SAML Response" do
    end

    it "should create an Encrypted, signed SAML Response" do
      saml_response = subject.test_encode_response(principal)
      expect(saml_response).to_not match(/\s/)

      rubysaml_response = OneLogin::RubySaml::Response.new(
        saml_response,
        { private_key: SamlIdp::Default::SERVICE_PROVIDER_KEY }
      )
      expect(rubysaml_response.name_id).to eq("foo@example.com")
      expect(rubysaml_response.issuer).to eq("http://example.com")
      rubysaml_response.settings = saml_settings
      expect(rubysaml_response.is_valid?).to be_truthy
      nokogiri_doc = Nokogiri::XML(rubysaml_response.document.to_s)
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
        # TODO(awong): This should not modify self.signature_opts as it causes
        # test ordering dependencies.
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

  context "Single Logout" do
    before(:each) do
      saml_request = Base64.strict_encode64(SamlIdp::LogoutRequestBuilder.new(
        '_response_id',
        'localhost:3000',
        'http://localhost:1337/saml/logout',
        'himom',
        'some_qualifier',
        'abc123index',
        subject.signature_opts).build.to_xml
      )
      post :test_saml_request, { SAMLRequest: saml_request }
    end

    it "should generate a signed LogoutResponse to the request" do
      signed_doc = Saml::XML::Document.parse(subject.test_response_doc(nil).to_xml)
      cert = OpenSSL::X509::Certificate.new(subject.signature_opts[:cert])
      fingerprint = OpenSSL::Digest::SHA256.new(cert.to_der).hexdigest
      expect(signed_doc.signed?).to be_truthy
      expect(signed_doc.valid_signature?(fingerprint)).to be_truthy
      expect(signed_doc.at_xpath('/samlp:LogoutResponse', samlp: Saml::XML::Namespaces::PROTOCOL)).to be_present
      status_node = signed_doc.at_xpath('/samlp:LogoutResponse/samlp:Status/samlp:StatusCode',
                                        samlp: Saml::XML::Namespaces::PROTOCOL)
      expect(status_node).to be_present
      expect(status_node.attributes["Value"].value).to eql(Saml::XML::Namespaces::Statuses::SUCCESS)
    end
  end
end
