require 'spec_helper'
module SamlIdp
  describe ServiceProvider do
    subject { described_class.new attributes }
    let(:attributes) { {} }

    it { should respond_to :fingerprint }
    it { should respond_to :metadata_url }
    it { should respond_to :assertion_consumer_logout_service_url }
    it { should_not be_valid }

    describe "with attributes" do
      let(:attributes) { { fingerprint: fingerprint, metadata_url: metadata_url } }
      let(:fingerprint) { Default::SP_FINGERPRINT }
      let(:metadata_url) { "http://localhost:3000/metadata" }
      let(:assertion_consumer_logout_service_url) { 'http://localhost:3000/saml/logout' }

      it "has a valid fingerprint" do
        subject.fingerprint.should == fingerprint
      end

      it "has a valid metadata_url" do
        subject.metadata_url.should == metadata_url
      end

      it { should be_valid }
    end
  end
end
