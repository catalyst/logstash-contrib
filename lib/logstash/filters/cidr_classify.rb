# encoding: utf-8
require "logstash/filters/base"
require "ipaddr"

class LogStash::Filters::CIDRClassify < LogStash::Filters::Base

  config_name "cidr_classify"
  milestone 1

  # The IP address to check, in sprintf format.
  config "address", :validate => :string, :required => true

  # A map between network names and their network IP addresses.
  # *address* will be checked efficiently against all of these.
  config "networks", :validate => :hash, :required => true

  # The field to write the matched networks to.
  # The names of the matched networks, in order from the most
  # vague to the most specific, seperated by dashes will be
  # written.
  config "target", :validate => :string, :required => true

  public
  def register
    # Parse and sort networks.
    networks = []
    @networks.each_pair do |key, value|
      begin
        network = IPAddr.new(value)
      rescue ArgumentError => e
        @logger.error("Invalid network address", :address => value)
        return
      end

      # Organize nodes into a tree in order to achieve better construction and
      # filtering performance.
      #
      # Each parent subnet should contain it's child subnets in this tree.
      subnets = networks
      while subnets.length > 0
        # Find the subnet to add this network to.
        subnet = find(subnets, network)

        if subnet
          subnets = subnet[:children]
          next
        else
          break # Found it!
        end
      end

      # We need to keep the list sorted for the find method to benefit from
      # binary search. Also some siblings may belong under the network we're
      # adding so we'll have to check that.
      data = {:name => key, :network => network, :children => []}

      # Use insertion sort to add data to subnets.
      index = 0
      index += 1 while index < subnets.length && subnets[index][:network] < network

      # Entries must be unique
      if index < subnets.length && subnets[index][:network] == network
        @logger.warn("Duplicate network address, ignoring.", :network => network)
      end

      # Given subnets is sorted, we should find any siblings that should be moved
      # under network directly after it.
      # A couple of tricks are used to avoid shifting entries around. These will
      # be commented.
      insertAt = index
      inserted_data = false
      while index < subnets.length && network.include?(subnets[index][:network])
        data[:children].push subnets[index] # Add under network.

        if inserted_data
          # Wait until we've finished going over the list to shift later indices down.
          subnets[index] = nil
        else
          # Take this chance to insert data into subnets without shifting data in memory.
          subnets[index] = data
          inserted_data = true
        end

        index += 1 # Check next index
      end

      if inserted_data
        # We may have left holes, fill them.
        subnets.compact!
      else
        # We still need to insert data.
        subnets.insert(insertAt, data)
      end
    end

    @subnets = networks
  end

  public
  def filter(event)
    return unless filter?(event)

    address = event.sprintf(@address)
    begin
      address = IPAddr.new(address)
    rescue ArgumentError => e
      @logger.warn("Invalid IP address, ignoring", :address => @address, :event => event)
      return
    end

    network_path = []
    subnets = @subnets
    while subnets.length
      # Find the subnet to add this network to
      subnet = find(subnets, address)

      if subnet
        network_path.push subnet[:name]
        subnets = subnet[:children]
        next
      else
        break # found it
      end
    end

    if network_path.length > 0
      event[@target] = network_path.join("-")
      filter_matched(event)
    else
      # Do not modify
    end
  end

  private
  def find(subnets, address)
    # Use a binary search, requires a sorted list.
    min = 0
    max = subnets.length - 1 # Maximum possible index

    while max >= min
      mid = min + (max - min) / 2
      if subnets[mid][:network].include?(address)
        return subnets[mid]
      elsif subnets[mid][:network] < address
        min = mid + 1
      else
        max = mid - 1
      end
    end
    return nil
  end
end
