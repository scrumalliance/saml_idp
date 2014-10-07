# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "saml_idp/version"

Gem::Specification.new do |s|
  s.name = %q{saml_idp}
  s.version = SamlIdp::VERSION
  s.platform = Gem::Platform::RUBY
  s.authors = ["Jon Phenow"]
  s.email = %q{jon.phenow@sportngin.com}
  s.homepage = %q{http://github.com/sportngin/saml_idp}
  s.summary = %q{SAML Indentity Provider in ruby}
  s.description = %q{SAML IdP (Identity Provider) library in ruby}
  s.date = Time.now.utc.strftime("%Y-%m-%d")
  s.files = Dir.glob("app/**/*") + Dir.glob("lib/**/*") + [
     "LICENSE",
     "README.md",
     "Gemfile",
     "saml_idp.gemspec"
  ]
  s.license = "LICENSE"
  s.test_files = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]
  s.rdoc_options = ["--charset=UTF-8"]
  s.add_dependency('activesupport')
  s.add_dependency('uuid')
  s.add_dependency('httparty')
  s.add_dependency('nokogiri')
#  s.add_dependency('nokogiri-xmlsec')

  s.add_development_dependency "rake"
  s.add_development_dependency "simplecov"
  s.add_development_dependency "rspec", "~> 3"
#  s.add_development_dependency "ruby-saml", "~> 0.8"
  s.add_development_dependency("rails", "~> 3.2")
  s.add_development_dependency("capybara")
  s.add_development_dependency("timecop")
  s.add_development_dependency("guard-bundler")
  s.add_development_dependency("guard-rspec")
  s.add_development_dependency("pry-byebug")
  s.add_development_dependency("equivalent-xml")
end

