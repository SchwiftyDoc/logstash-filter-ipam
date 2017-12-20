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

    sample("ip" => "212.24.215.123") do
      expect(subject).to include("subnets")
      #expect(subject.get('subnets')).to eq('Hello World')
    end
  end
end
