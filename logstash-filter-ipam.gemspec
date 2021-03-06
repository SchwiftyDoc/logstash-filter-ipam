Gem::Specification.new do |s|
  s.name          = 'logstash-filter-ipam'
  s.version       = '0.1.6'
  s.licenses      = ['Apache-2.0']
  s.summary       = 'Correlation with IPAM.'
  s.description   = 'Filter that allows getting subnets from existing file extracted from IPAM for an IP address.'
  s.homepage      = 'https://github.com/SchwiftyDoc/logstash-filter-ipam'
  s.authors       = ['Corentin Dekimpe']
  s.email         = 'cdekimpe@telkea.com'
  s.require_paths = ['lib']

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','CONTRIBUTORS','Gemfile','LICENSE','NOTICE.TXT']
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "filter" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core-plugin-api", "~> 2.0"
  s.add_runtime_dependency "activerecord", "~> 4.0.0"
  s.add_development_dependency 'logstash-devutils'
end