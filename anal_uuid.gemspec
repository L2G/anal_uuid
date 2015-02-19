# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'anal_uuid/version'

Gem::Specification.new do |spec|
  spec.name          = 'anal_uuid'
  spec.version       = AnalUUID::VERSION
  spec.authors       = ['Lawrence Leonard Gilbert']
  spec.email         = ['larry@L2G.to']
  spec.summary       = 'Forensic analysis of UUIDs'
  spec.description   = 'Analyze UUIDs and deduce how they were most likely'\
                       'generated'
  spec.homepage      = ''
  spec.license       = 'MIT'

  spec.files         = `git ls-files -z`.split("\u0000")
  spec.executables   = spec.files.grep(/^bin\//) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(/^(test|spec|features)\//)
  spec.require_paths = ['lib']

  spec.add_development_dependency 'bundler', '~> 1.7'
  spec.add_development_dependency 'rake', '~> 10.0'
end
