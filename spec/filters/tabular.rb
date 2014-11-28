# encoding: utf-8
require "test_utils"
require "logstash/filters/tabular"

describe LogStash::Filters::Tabular do
  extend LogStash::RSpec

  describe "parses tabbed files (default config)" do
    config <<-CONFIG
      filter {
        tabular { }
      }
    CONFIG

    sample("message" => "fubar") do
      insist { subject["column1"] } == "fubar"
    end

    sample("message" => "su\tper\tcal\ti\tfra\tga\tlis\ttic\tex\tpe\tala\tdo\tcious") do
      insist { subject["column1"] } == "su"
      insist { subject["column2"] } == "per"
      insist { subject["column3"] } == "cal"
      insist { subject["column4"] } == "i"
      insist { subject["column5"] } == "fra"
      insist { subject["column6"] } == "ga"
      insist { subject["column7"] } == "lis"
      insist { subject["column8"] } == "tic"
      insist { subject["column9"] } == "ex"
      insist { subject["column10"] } == "pe"
      insist { subject["column11"] } == "ala"
      insist { subject["column12"] } == "do"
      insist { subject["column13"] } == "cious"
    end

    sample("message" => "# This should be dropped") do
      insist { subject } == nil
    end
  end

  describe "assigns columns correctly" do
    config <<-CONFIG
      filter {
        tabular {
          columns => ["first", "last"]
        }
      }
    CONFIG

    sample("message" => "john") do
      insist { subject["first"] } == "john"
      insist { subject.include?("column_1") } == false
      insist { subject.include?("last") } == false
    end

    sample("message" => "silvester\tmccoy") do
      insist { subject["first"] } == "silvester"
      insist { subject["last"] } == "mccoy"
      insist { subject.include?("column1") } == false
      insist { subject.include?("column2") } == false
    end

    sample("message" => "this\tis\tnot\ta\tname") do
      insist { subject["first"] } == "this"
      insist { subject["last"] } == "is"
      insist { subject["column3"] } == "not"
      insist { subject["column4"] } == "a"
      insist { subject["column5"] } == "name"
      insist { subject.include?("column1") } == false
      insist { subject.include?("column2") } == false
    end
  end
end
