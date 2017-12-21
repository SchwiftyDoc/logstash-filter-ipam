# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "ipaddr"
require "mysql"
require "json"

# This  filter will replace the contents of the default
# message field with whatever you specify in the configuration.
#
# It is only intended to be used as an .
class LogStash::Filters::Ipam < LogStash::Filters::Base

  # Setting the config_name here is required. This is how you
  # configure this filter from your Logstash config.
  config_name "ipam"

  # Logstash filter options.
  config :ip, :validate => :string, :required => true
  config :field, :validate => :string, :default => "subnets"
  config :gateway, :validate => :boolean, :default => false

  # Mysql connection options.
  config :mysql_host, :validate => :string, :required => true
  config :mysql_user, :validate => :string, :required => true
  config :mysql_pass, :validate => :string, :required => true
  config :mysql_db, :validate => :string, :default => "phpipam"

  # File storage options.
  config :time_reset, :validate => :number, :default => 600
  config :file, :validate => :string, :default => "/tmp/logstash-filter-ipam.json"


  public
  def register
    # Check if the IP string is an actual IP, or stop process
    begin
      @ip = IPAddr.new(@ip)
    rescue ArgumentError => e
      @logger.warn("Invalid IP address, skipping", :address => @ip, :event => event)
      nil
    end
  end # def register

  private
  def downloadIpamSubnets(event)
    begin
      client = Mysql::Client.new(:host => @mysql_host,
                                 :username => @mysql_user,
                                 :password => @mysql_pass,
                                 :database => @mysql_db)
      result = client.query("SELECT id,  FROM subnets")
      client.close()
      return JSON.parse(result)
    rescue
        @logger.warn("Impossible to retrieve data from Mysql.", :address => @mysql_host, :event => event)
    end
  end

  private
  def getSubnets(event)
    # Reading files
    begin
      file = File.read(@file)
      json  JSON.parse(file)
      return json["subnets"]
    rescue
      @logger.warn("Impossible to read into file.", :address => @file, :event => event)
    end
  end

  private
  def checkIpSubnets(ip, subnets)
    results = Array.new
    subnets.each do |sub|
      if !@gateway && sub['subnet'] == "0.0.0.0"
        next
      end
      if IPAddr.new(sub['subnet'] + "/" + sub['netmask'].to_s).include?(ip)
        results.push(sub)
      end
    end
    return results
  end

  private
  def checkFile(event)
    if (!File.exist?(@file) || File.mtime(@file).utc < (Time.now - @time_reset).utc)
      begin
        file = File.open(@file, 'w')
        file.write(downloadIpamSubnets(event))
      rescue
        @logger.warn("Impossible to write into file.", :address => @file, :event => event)
      end
    end
  end

  public
  def filter(event)
    # Check file
    #   if doesn't exist => create with content.
    #   if need reset => update content.
    checkFile(event)

    # Get Subnets Checking the IP
    # if can't read => Warning
    # if gateway is false => won't register "0.0.0.0" subnets
    ipamSubnets = getIpamSubnets(event)
    subnets = checkIpSubnets(@ip, subnets)

    # Set field only if there is some subnets checked.
    if subnets.length > 0
      event.set(@field, subnets)
    else
      # filter_matched should go in the last line of our successful code
      filter_matched(event)
    end
  end # def filter
end # class LogStash::Filters::Ipam
