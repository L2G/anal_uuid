# (ParseUUID is the ancestor of AnalUUID.)
#-----------------------------------------

# Parse a UUID as defined in IETF RFC 4122, "A Universally Unique IDentifier
# (UUID) URN Namespace" by Leach, Mealling, and Salz
# (http://www.ietf.org/rfc/rfc4122.txt)
#
# Other references:
#
# "Universal Unique Identifier". The Open Group. CDE 1.1: Remote Procedure Call
# (http://pubs.opengroup.org/onlinepubs/9629399/apdxa.htm).
#
# "Privilege (Authorisation) Services." The Open Group. DCE 1.1: Authentication
# and Security Services
# (http://pubs.opengroup.org/onlinepubs/9668899/chap5.htm#tagcjh_08_02_01_01).
#
class ParseUUID
  # The reference time for the UUID epoch, defined as 15 October 1582, 00:00
  # UTC (even though UTC itself was not formalized until 1960!)
  EPOCH = Time.gm(1582, 10, 15)

  # The earliest year a UUID could have reasonably been generated according to
  # the spec described in the RFC.
  EARLIEST_YEAR = 1990

  # The lowest 32 bits of the timestamp value
  attr_reader :time_low

  # The 16 bits of the timestamp value that come between time_hi_and_version
  # and time_low
  attr_reader :time_mid

  # The 4 bits representing the version, plus the highest 12 bits of the
  # timestamp value, for a total of 16 bits
  attr_reader :time_hi_and_version

  # The 8 bits representing variant and the highest bits of the clock sequence
  # value
  attr_reader :clock_seq_hi_and_reserved

  # The lowest 8 bits of the clock sequence value
  attr_reader :clock_seq_low

  # 4 insignificant bits followed by the 60-bit node value
  attr_reader :node

  # Constructor that takes a UUID string
  def initialize(uuid)
    (/^
      (?<chunk1>[0-9a-f]{8}) -
      (?<chunk2>[0-9a-f]{4}) -
      (?<chunk3>[0-9a-f]{4}) -
      (?<chunk4>[0-9a-f]{2})
      (?<chunk5>[0-9a-f]{2}) -
      (?<chunk6>[0-9a-f]{12})
    $/ix =~ uuid) || fail(ArgumentError, "Not in UUID format: #{uuid}")

    @time_low               = chunk1.hex
    @time_mid               = chunk2.hex
    @time_hi_and_version    = chunk3.hex
    @clock_seq_hi_and_reserved = chunk4.hex
    @clock_seq_low          = chunk5.hex
    @node                   = chunk6.hex
  end

  def analysis
    report = analysis_summary + "\n\n"
    report << sprintf("┌┬┬┬┬┬┬┬────────────────────┬┬┬┬┬┬┬┐\n")
    report << sprintf("││││││││ ┌┬┬┬───────────┬┬┬┐││││││││\n")
    report << sprintf("││││││││ ││││  ┌┬┬── %015x (%s)*\n", timestamp_value, time_desc)
    report << sprintf("││││││││ ││││  │││\n")
    report << "#{self}\n"
    clock_seq_bits = clock_seq_hi_and_reserved << 8 | clock_seq_low
    report << sprintf("              │    ││││\n")
    report << sprintf("              │    └└└└── = %016b\n",
                      clock_seq_bits, clock_seq_bits)
    clock_seq_desc.each do |line|
      report << sprintf("              │             %s\n", line)
    end
    report << sprintf("              └─────── = version %d (%s)\n",
                      version, version_desc)
    report << sprintf("\n* %015x is %d in decimal. It represents\n",
                      timestamp_value, timestamp_value)
    report << sprintf("  %d.%01d microseconds since %s.\n",
                      timestamp_value / 10, timestamp_value % 10, EPOCH.to_s)
    if version != 1
      report << "  This is meaningless as a timestamp except in a version 1 UUID.\n"
    elsif !reasonable_time?
      report << "  This is an unlikely time for a UUID to have been generated\n"
      report << "  because it lies outside the time window from #{EARLIEST_YEAR} to present.\n"
    end
    report
  end

  def analysis_summary
    if seems_valid?.nil?
      return "This doesn't seem like a UUID generated according to RFC 4122."
    end

    if seems_valid? == false
      return 'This is DEFINITELY NOT a UUID generated according to RFC 4122.'
    end

    if nil_uuid?
      return 'This UUID is specifically defined by RFC 4122 as the "nil" UUID.'
    end

    if seems_valid_microsoft?
      return 'This seems like a UUID from Microsoft.'
    end

    case version
    when 1
      return 'This seems like a UUID generated according to RFC 4122 or DCE.'
    when 2
      return 'This seems like a UUID generated according to DCE Security.'
    else
      return 'This seems like a UUID generated according to RFC 4122.'
    end
  end

  def clock_seq_desc
    desc = []
    if variant_ncs?
      desc << '0............... = NCS backward compatibility'
    elsif variant_reserved?
      desc << '111............. = reserved'
    elsif variant_microsoft?
      desc << '110............. = Microsoft backward compatibility'
    elsif variant_rfc_4122?
      desc << '10.............. = RFC 4122/DCE'
      sub_desc = [
        "%d (???)",                  # 0
        '%d (clock sequence value)', # 1
        '%d (???)',                  # 2
        'MD5 hash bits 66-95',       # 3
        'random bits',               # 4
        'SHA-1 hash bits 66-95'      # 5
      ]
      desc << sprintf('..%014b = ' + (sub_desc[version] || sub_desc[0]),
                      clock_sequence_value, clock_sequence_value
                     )
    end
    desc
  end

  def clock_sequence_value
    @clock_sequence_value ||=
      ((@clock_seq_hi_and_reserved & 0b111111) << 8) | @clock_seq_low
  end

  # Whether this is the nil UUID (00000000-0000-0000-0000-000000000000).
  def nil_uuid?
    [time_low, time_mid, time_hi_and_version, clock_seq_hi_and_reserved,
     clock_seq_low, node].all? { |n| n == 0 }
  end

  # Whether the interpretation of the timestamp seems reasonable; i.e., it
  # represents a time since the start of {EARLIEST_YEAR} that is not more than
  # an hour into the future.
  def reasonable_time?
    time.year >= EARLIEST_YEAR && time < Time.now + 3600
  end

  # Whether this UUID seems to have been generated in conformance with the RFC.
  def seems_valid?
    return true if nil_uuid?
    return seems_valid_microsoft? if variant_microsoft?
    return false if undefined_version? && variant_rfc_4122?
    if variant_rfc_4122?
      version == 1 ? reasonable_time? : !undefined_version?
    else
      nil
    end
  end

  def seems_valid_microsoft?
    return nil unless variant_microsoft?
    # Microsoft's predefined GUID for IUnknown
    # (https://en.wikipedia.org/wiki/Globally_Unique_Identifier)
    return true if clock_sequence_value == 0 && timestamp_value == 0 &&
                   node == 70
  end

  # The date and time represented by the timestamp value, as defined by the
  # RFC (the number of 100-nanosecond intervals since {EPOCH}.)  Unlikely to be
  # meaningful if version is not 1.
  def time
    @time ||= EPOCH + timestamp_value / 1e7 # 100-ns intervals
  end

  def time_desc
    if seems_valid? && version == 1
      "= #{time}"
    else
      "≍ #{time}"
    end
  end

  # The full, 60-bit timestamp value as an unsigned integer.
  def timestamp_value
    @timestamp_value ||=
      ((@time_hi_and_version & 0b1111_1111_1111) << 48) |
      (@time_mid << 32) | @time_low
  end

  def to_i
    sprintf('%08x%04x%04x%02x%02x%012x',
            @time_low,
            @time_mid,
            @time_hi_and_version,
            @clock_seq_hi_and_reserved,
            @clock_seq_low,
            @node).hex
  end

  def to_s
    sprintf('%08x-%04x-%04x-%02x%02x-%012x',
            @time_low,
            @time_mid,
            @time_hi_and_version,
            @clock_seq_hi_and_reserved,
            @clock_seq_low,
            @node)
  end

  def to_guid
    "{#{to_s.upcase}}"
  end

  def to_oid
    "2.25.#{to_i}"
  end

  def to_urn
    'urn:uuid:' + to_s
  end

  def undefined_version?
    version < 1 || version > 5
  end

  # The value of the 3 variant bits in the UUID
  def variant_bits
    @variant_bits ||= @clock_seq_hi_and_reserved >> 5
  end

  def variant_desc
    desc = '0xx = NCS backward compatibility' if variant_ncs?
    desc = '111 = reserved' if variant_reserved?
    desc = '110 = Microsoft backward compatibility' if variant_microsoft?
    desc = '10x = RFC 4122/DCE' if variant_rfc_4122?
    desc ||= sprintf('%03b = undefined', variant_bits)
    desc
  end

  # Whether the variant bits match the definition of "NCS backward
  # compatibility." ("NCS" is not defined in the RFC, but probably refers to
  # the AIX Network Computing System.)
  def variant_ncs?
    variant_bits & 0b100 == 0b000
  end

  # Whether the variant bits match the value reserved for future use.
  def variant_reserved?
    variant_bits == 0b111
  end

  # Whether the variant bits match the value reserved for Microsoft backward
  # compatibility.
  def variant_microsoft?
    variant_bits == 0b110
  end

  # Whether the variant bits are set exactly as specified by RFC 4122 (and,
  # by extension, DCE).
  def variant_rfc_4122?
    variant_bits & 0b110 == 0b100
  end

  def version
    @version ||= @time_hi_and_version >> 12
  end

  def version_desc
    return 'undefined' if undefined_version?
    case version
    when 1
      'RFC 4122/DCE, time-based'
    when 2
      'DCE Security, embedded POSIX UID'
    when 3
      'RFC 4122, name-based MD5 hash'
    when 4
      'RFC 4122, randomly-generated'
    when 5
      'RFC 4122, name-based SHA-1 hash'
    else
      'INTERNAL ERROR'
    end
  end
end
