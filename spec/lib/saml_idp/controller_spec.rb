# encoding: utf-8
require 'spec_helper'

describe SamlIdp::Controller do
  include SamlIdp::Controller

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
      saml_response = encode_response(principal)
      response = OneLogin::RubySaml::Response.new(
        saml_response,
        { private_key: SamlIdp::Default::SERVICE_PROVIDER_KEY })
      response.name_id.should == "foo@example.com"
      response.issuer.should == "http://example.com"
      response.settings = saml_settings
      response.is_valid?.should be_truthy
    end

    [:sha1, :sha256, :sha384, :sha512].each do |algorithm_name|
      skip "should create a SAML Response using the #{algorithm_name} algorithm" do
        self.algorithm = algorithm_name
        saml_response = encode_response(principal)
        response = OneLogin::RubySaml::Response.new(
          saml_response,
          { private_key: SamlIdp::Default::SERVICE_PROVIDER_KEY })
        response.name_id.should == "foo@example.com"
        response.issuer.should == "http://example.com"
        response.settings = saml_settings
        response.is_valid?.should be_truthy
      end
    end
  end

end
