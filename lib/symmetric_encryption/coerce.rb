module SymmetricEncryption
  # For coercing data types to from strings
  module Coerce
    TYPE_MAP = {
      string:   String,
      integer:  Integer,
      float:    Float,
      decimal:  BigDecimal,
      datetime: DateTime,
      time:     Time,
      date:     Date
    }.freeze

    # Coerce given value into given type
    # Does not coerce json or yaml values
    def self.coerce(value, type, from_type = nil)
      return value if value.nil? || (value == "")

      from_type ||= value.class
      case type
      when :json
        value
      when :yaml
        value
      else
        coercer = Coercible::Coercer.new
        coercer[from_type].send("to_#{type}".to_sym, value)
      end
    end

    # Uses coercible gem to coerce values from strings into the target type
    # Note: if the type is :string, then the value is returned as is, and the
    #   coercible gem is not used at all.
    def self.coerce_from_string(value, type)
      return value if value.nil? || (value == "")

      case type
      when :string
        value
      when :json
        JSON.load(value)
      when :yaml
        YAML.load(value)
      else
        coerce(value, type, String)
      end
    end

    # Uses coercible gem to coerce values to strings from the specified type
    # Note: if the type is :string, and value is not nil, then #to_s is called
    #   on the value and the coercible gem is not used at all.
    def self.coerce_to_string(value, type)
      return value if value.nil? || (value == "")

      case type
      when :string
        value.to_s
      when :json
        value.to_json
      when :yaml
        value.to_yaml
      else
        coerce(value, :string, coercion_type(type, value))
      end
    end

    # Returns the correct coercion type to use for the specified symbol and value
    def self.coercion_type(symbol, value)
      if symbol == :boolean
        value.class
      else
        TYPE_MAP[symbol]
      end
    end
  end
end
