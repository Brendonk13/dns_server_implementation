
"""
This file contains common data for programs to import
"""

ENDIAN = 'big'

# note that I only implemented requests for A records currently
QUERY_TYPES = {
    'a':      1,   # a host address
    'ns':     2,   # an authoritative name server
    'md':     3,   # a mail destination (Obsolete - use MX)
    'mf':     4,   # a mail forwarder (Obsolete - use MX)
    'cname':  5,   # the canonical name for an alias
    'soa':    6,   # marks the start of a zone of authority
    'mb':     7,   # a mailbox domain name (EXPERIMENTAL)
    'mg':     8,   # a mail group member (EXPERIMENTAL)
    'mr':     9,   # a mail rename domain name (EXPERIMENTAL)
    'null':   10,  # a null RR (EXPERIMENTAL)
    'wks':    11,  # a well known service description
    'ptr':    12,  # a domain name pointer
    'hinfo':  13,  # host information
    'minfo':  14,  # mailbox or mail list information
    'mx':     15,  # mail exchange
    'txt':    16,  # text strings
}
