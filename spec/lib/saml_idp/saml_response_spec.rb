require 'spec_helper'
module SamlIdp
  describe SamlResponse do
    it "has a valid unencrypted build" do
     response = SamlResponse.new("a_reference_id",
                                  "a_responce_id",
                                  "http://localhost",
                                  "a_name_id",
                                  "http://localhost/audience",
                                  "a_saml_request_id",
                                  "http://localhost/acs",
                                  :sha256,
                                  Saml::XML::Namespaces::AuthnContext::ClassRef::PASSWORD,
                                  nil)
      # Don't throw.
      response.build
    end

    it "has a valid encrypted build" do
     response = SamlResponse.new("a_reference_id",
                                  "a_responce_id",
                                  "http://localhost",
                                  "a_name_id",
                                  "http://localhost/audience",
                                  "a_saml_request_id",
                                  "http://localhost/acs",
                                  :sha256,
                                  Saml::XML::Namespaces::AuthnContext::ClassRef::PASSWORD,
                                  fixture('service_provider.cert'))
      # Don't throw.
      response.build
    end
  end
end
