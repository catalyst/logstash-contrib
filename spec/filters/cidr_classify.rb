# encoding: utf-8
require "test_utils"
require "logstash/filters/cidr_classify"

describe LogStash::Filters::CIDRClassify do
  extend LogStash::RSpec

  describe "IPv4 match" do
    config <<-CONFIG
      filter {
        cidr_classify {
          address => "%{client_ip}"
          networks => {
            "c" => "192.168.0.0/24"
          }
          target => "class"
        }
      }
    CONFIG

    sample("client_ip" => "192.168.0.30") do
      insist { subject["class"] } == "c"
    end
  end

  describe "IPv4 non-match" do
    config <<-CONFIG
      filter {
        cidr_classify {
          address => "%{client_ip}"
          networks => {
            "c" => "192.168.0.0/24"
          }
          target => "class"
        }
      }
    CONFIG

    sample("client_ip" => "123.52.122.33") do
      insist { subject["class"] }.nil?
    end
  end

  describe "IPv4 multi-match" do
    config <<-CONFIG
      filter {
        cidr_classify {
          address => "%{client_ip}"
          networks => {
            "subnet1" => "123.35.0.0/16"
            "subsubnet2" => "123.52.122.0/24"
            "subsubnet1" => "123.35.53.0/24"
            "net" => "123.0.0.0/8"
            "subnet2" => "123.52.0.0/16"
          }
          target => "net"
        }
      }
    CONFIG

    sample("client_ip" => "123.52.122.33") do
      insist { subject["net"] } == "net-subnet2-subsubnet2"
    end

    sample("client_ip" => "123.35.53.231") do
      insist { subject["net"] } == "net-subnet1-subsubnet1"
    end
  end
end
