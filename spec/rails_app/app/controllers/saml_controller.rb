require 'pry'
class SamlController < ApplicationController

  def consume
    response = OneLogin::RubySaml::Response.new(
      params[:SAMLResponse],
      { private_key: SamlIdp::Default::SERVICE_PROVIDER_KEY })
    render :text => response.name_id
  end

end
