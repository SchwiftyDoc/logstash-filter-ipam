# encoding: utf-8
require "active_record"
require "activerecord-jdbcmysql-adapter"
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
  config_name "ipam"

  # Logstash filter options.
  config :ip, :validate => :string, :required => true
  config :field, :validate => :string, :default => "subnets"
  config :gateway, :validate => :boolean, :default => false

  # Mysql connection options.
  config :mysql_host, :validate => :string, :required => true
  config :mysql_port, :validate => :number, :default => 3306
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
      # Create connection to the MySQL Database
      ActiveRecord::Base.establish_connection ({
          :adapter => "mysql",
          :host => @mysql_host,
          :username => @mysql_user,
          :password => @mysql_pass,
          :database => @mysql_db
      })

      # Get all the subnets from the Table
      subnets = ActiveRecord::Base.connection.exec_query("SELECT id, subnet, mask, description FROM subnets")

      # Set subnets into IPv4 address format
      subnets.each do |sub|
        isub = Integer(sub['subnet'])
        if isub >= 0 && isub <= 4294967295
          sub['subnet'] = IPAddr.new(isub, Socket::AF_INET).to_s
          sub['ipv4'] = true
        else
          sub['ipv4'] = false
          @logger.warn("Logger : Not compatible with IPv4.", :address => sub['subnet'], :event => event)
        end
      end

      # Parse result to create a JSON string
      return subnets.to_json
    rescue
        @logger.warn("Impossible to retrieve data from MySQL.", :address => @mysql_host, :event => event)
    end
    return json
  end

  private
  def getSubnets(event)
    # Reading files
    begin
      file = File.read(@file)
      return  JSON.parse(file)
    rescue
      @logger.warn("Impossible to read into file.", :address => @file, :event => event)
    end
  end

  private
  def checkIpSubnets(ip, subnets)
    results = Array.new
    subnets.each do |sub|
      if !sub['ipv4']
        next
      end
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

    # Get Subnets from updated file
    #   if can't read => Warning
    ipamSubnets = getIpamSubnets(event)

    # Get Subnets that contains IP
    #   if @gateway => Get 0.0.0.0 subnets
    #   else        => Don't get those subnets
    #   if !ipv4 => Don't handle those subnets
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
