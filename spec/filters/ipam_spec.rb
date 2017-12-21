# encoding: utf-8
require_relative '../spec_helper'
require "logstash/filters/ipam"

describe LogStash::Filters::Ipam do
  describe "Create subnets array from IP" do
    let(:config) do <<-CONFIG
      filter {
        ipam {
          ip => "212.24.215.123"
        }
      }
    CONFIG
    end

    sample("ip" => "212.24.215.123",
           "mysql_host" => "172.19.0.19",
           "mysql_user" => "kibana",
           "mysql_pass" => "QZQxf4XQGni6",) do
      expect(subject).to include("subnets")
      expect(subject.get('subnets')).to !eq('')
    end
  end
end
