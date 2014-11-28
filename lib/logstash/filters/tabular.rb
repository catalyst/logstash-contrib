# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

# The tabular filter splits each line by tabs or other delimiter
# And assigns the results to specified columns in much the same way
# csv does. 
class Logstash::Filters::Tabular < Logstash::Filters::Base
  config_name "tabular"
  milestone 0
  
  # The tabular in the value of the source will be expanded into a 
  # data structure.
  config :source, :validate => :string, :default => "message"
  
  # Defines a list of column names which will be mapped to values
  # from each row in order. If there's too few not all columns will
  # appear in the result. If there's too many values, they will be 
  # named column1, column2, etc.
  config :columns, :validate => :array, :default => []
  
  # Defines the character(s) used to seperate values. Defaults to "\t".
  config :seperator, :validate => :string, :default => "\t"
  
  # Defines the target field for placing the data. 
  # Defaults to writing to the root of the element. 
  config :target, :validate => :string
  
  # Defines the prefix for which lines will be dropped. Defaults to "#".
  config :comment_char, :validate => :string, :default => "#"
  
  public
  def register
    
    # Nothing to do here
    
  end
  
  public
  def filter(event)
    return unless filter?(event)
    
    @logger.debug("Running tabular filter", :event => event)
    
    matches = 0
    
    if event[@source]
      if event[@source].is_a?(string)
        event[@source] = [event[@source]]
      end
      
      if event[@source].length > 1
        @logger.warn("tabular filter only works on fields of length 1",
                      :source => @source, :value => event[@source],
                      :event => event)
        return
      end
      
      raw = event[@source].first
      begin
        if raw.starts_with?(@comment_char)
          event.cancel
        end
      
        values = raw.split(@seperator)
        
        if @target.nil?
          dest = event
        else
          dest = event[@target] ||= {}
        end
        
        values.each_index do |i|
          field_name = @columns[i] || "column#{i+1}"
          dest[field_name] = values[i]
        end
        
        filter_matched(event)
      rescue => e:
        event.tag "_tabularparsefailure"
        @logger.warn("Trouble parsing tabular data", :source => @source, 
                    :raw => raw, :exception => e)
        return
      end # begin
    end # if
    
    @logger.debug("Event after tabular filter", :event => event)
    
  end # def filter
  
end # class Logstash::Filters::Tabular
