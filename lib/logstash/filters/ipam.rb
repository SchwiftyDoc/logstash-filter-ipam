# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "ipaddr"
require "json"

# This  filter will replace the contents of the default 
# message field with whatever you specify in the configuration.
#
# It is only intended to be used as an .
class LogStash::Filters::Ipam < LogStash::Filters::Base

  # Setting the config_name here is required. This is how you
  # configure this filter from your Logstash config.
  #
  # filter {
  #    {
  #     message => "My message..."
  #   }
  # }
  #
  config_name "ipam"
  
  # Replace the message with this value.
  config :ip, :validate => :string, :required => true
  config :file, :validate => :string, :default => "/opt/subnets/subnets.json"
  config :field, :validate => :string, :default => "subnets"


  public
  def register
    # Add instance variables
  end # def register

  public
  def filter(event)

    results = Array.new
    file = File.read(@file)
    json = JSON.parse(file)
    subnets = json["subnets"]

    ip = IPAddr.new(@ip)
    subnets.each do |sub|
      if IPAddr.new(sub['subnet'] + "/" + sub['netmask']) === ip
        results.push(sub)
      end
    end

    # Set field only if there is some subnets checked.
    if results.length > 0
      event.set(@field, results)
    end

    # filter_matched should go in the last line of our successful code
    filter_matched(event)
  end # def filter
end # class LogStash::Filters::Ipam
