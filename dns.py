import socket
import pathlib
import json
from functools import reduce
from operator import add

# DNS SPECIFICATION: https://www.ietf.org/rfc/rfc1035.txt


"""
Todo:
    1. format -- delete prints
    2. maybe split op_code into a record
    3. delete shit that isnt used (extract_flags byte2??)

-- setup actual website then add in info for that zone file !!

def record_to_bytes(domain_parts, query_type, record_ttl, record_value):
    ---- delete domain_parts argument
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





def concat_to_byte(*args):
    # concatenate string arguments and convert to a byte
    # here to prevent repeated ugliness in extract_flags
    return  int(''.join(args), 2).to_bytes(1, byteorder=ENDIAN)


def extract_bits(byte, start_bit, end_bit):
    extracted = ''
    for bit in range(start_bit, end_bit):
        # iter 0: concat leftmost        bit from byte1
        # iter 1: concat second leftmost bit from byte1
        # ...
        extracted += str(ord(byte) & (1 << bit))
    return extracted


def flag_byte_1(query_byte):
    # mark that this is a response by setting this flag to 1
    query_or_response = '1'

    # op_code is set by the originator of a query and copied into the response
    op_code = extract_bits(query_byte, 1, 5)


    # 1 if the response is coming from a authoritative DNS server
    #   -- the response is coming from the server which owns the domain
    authoritative_answer = '1'

    # if truncation = 1 then this server must truncate the response due
    # to it being longer than 512 bytes and mark it as truncated
    # I assume (for now) that the responses will be short (current is only 77 bytes so seems fine for now)
    truncation = '0'

    # recursion_desired, set to 1 if the client is asking the server whether it offers recursion
    # we will just say no
    # we are supposed to get this value from the query but for simplicity just set to 0
    recursion_desired = '0'

    return concat_to_byte(
            query_or_response,
            op_code,
            authoritative_answer,
            truncation,
            recursion_desired,
    )


def flag_byte_2(query_byte):
    # recursion_available
    recursion_available = '0'

    # Z: reserved bits for future usage. must be zero in all queries and responses
    Z = '000'

    # response_code: indicates whether the query was successful
    response_code = '0000'

    return concat_to_byte(recursion_available, Z, response_code)


def extract_flags(flags):
    byte1, byte2 = (bytes(flag) for flag in flags)
    return flag_byte_1(byte1) + flag_byte_2(byte2)


def extract_question_domain(data):
    seen_chars = 0
    query_type_pos = 1
    expected_len = 0
    domain_string = ''
    domain_parts = []
    new_byte = True
    for byte in data:
        query_type_pos += 1
        if new_byte:
            new_byte = False
            expected_len = byte
            continue

        if byte != 0: # dont add the last byte (\x00) to domain_string
            domain_string += chr(byte)
        seen_chars += 1

        if seen_chars == expected_len:
            domain_parts.append(domain_string)
            domain_string = ''
            seen_chars = 0
            new_byte = True
        if byte == 0:
            break

    query_type = data[query_type_pos - 2: query_type_pos]

    return domain_parts, query_type


def load_zones():
    # zone_files = pathlib.Path('zones').glob('*zone')
    # print(zone_files)
    json_zone = {}
    for zone in pathlib.Path('zones').glob('*zone'):
        with open(zone) as zone_file:
            data = json.load(zone_file)
            zone_name = data["$origin"]
            json_zone[zone_name] = data
    # print(json_zone)
    return json_zone



def get_zone(domain):
    zone_data = load_zones()
    zone_name = '.'.join(domain) + '.'
    if zone_name not in zone_data:
        raise ValueError("This DNS server is not aware of the requested domain.")
    return zone_data[zone_name]


def get_A_records(data):
    domain, query_type = extract_question_domain(data)

    # this should always be 'a' !!! because first byte should always be zero since
    # this byte represents the query type
    # (0 for if question -- we extracted this val from question so always true)
    # and second byte should always be a one to mark that this is a IN class query
    for q_type, q_code in QUERY_TYPES.items():
        if q_code == int.from_bytes(query_type, ENDIAN):
            query_type = q_type
            # print(f'query type from question is: {query_type}')
            break
    else:
        # query_type = ''
        raise ValueError("Bad DNS request: query type value (QTYPE) not part of the specification")

    # query_type = 'a' if query_type == b'\x00\x01' else ''
    zone = get_zone(domain)

    return zone[query_type], query_type, domain


def create_header(query):
    """
    parse the queries binary query data to extract certain headers and flags
    """
    # 16 bit identifier that is generated by the client and copied in the server's reply
    transaction_id = query[:2]
    flags = extract_flags(query[2:4])

    # question_count: historically dns clients would ask multiple questions per query
    # nowadays they almost always just ask 1 q
    # the number 1  --  in 2 bytes
    question_count = b'\x00\x01'

    # answer_count: if there is more than 1 A record returned then says how many
    # think response records go here also
    records, _, _ = get_A_records(query[12:])
    answer_count = len(records).to_bytes(2, byteorder=ENDIAN)
    # query[12:]  -->  starting at this index is the domain name of the query


    # ns_count: number of name servers returned (think this is for recursive dns servers)
    # we arent going to send any name servers so this will be zero
    ns_count = (0).to_bytes(2, byteorder=ENDIAN)

    # ar_count: additional records countt the zone file??
    # not sending these for simplicity
    ar_count = (0).to_bytes(2, byteorder=ENDIAN)

    dns_header = reduce(add, (
            transaction_id,
            flags,
            question_count,
            answer_count,
            ns_count,
            ar_count
    ))


    print(dns_header)
    return dns_header


def get_dns_question(domain_parts, query_type):
    def query_name():
        # format: length of domain part, domain part, repeat .... \x0 to mark termination of domain name
        name_bytes = b''
        for domain_part in domain_parts:
            # mark the length of the part
            name_bytes += bytes([len(domain_part)])
            # add the characters
            for char in domain_part:
                name_bytes += ord(char).to_bytes(1, byteorder=ENDIAN)
        # mark termination of the domain_name
        return name_bytes + (0).to_bytes(1, byteorder=ENDIAN)


    q_bytes = query_name()

    q_bytes += (QUERY_TYPES[query_type]).to_bytes(2, byteorder=ENDIAN)

    # 2 bytes to mark the query class -- almost always "IN" -> Internet
    # (always for this server)
    q_bytes += (1).to_bytes(2, byteorder=ENDIAN)
    return q_bytes
    # print(q_bytes)


def record_to_bytes(domain_parts, query_type, record_ttl, record_value):
    # mark offset to domain_name as 12 bytes (compression)
    r_bytes = b'\xc0\x0c'

    if query_type == 'a':
        r_bytes += bytes([0]) + bytes([1])

    r_bytes += bytes([0]) + bytes([1])

    r_bytes += int(record_ttl).to_bytes(4, byteorder=ENDIAN)

    if query_type == 'a':
        r_bytes += bytes([0]) + bytes([4])

        for part in record_value.split('.'):
            r_bytes += bytes([int(part)])

    return r_bytes


def get_dns_body(records, query_type, domain_parts):
    dns_body = b''
    for record in records:
        print(record)
        dns_body += record_to_bytes(domain_parts, query_type, record["ttl"], record["value"])
    return dns_body


def response(query):
    dns_header = create_header(query)

    # 12 since the header is 12 bytes
    record_info = get_A_records(query[12:])
    records, query_type, domain_parts = record_info


    dns_question = get_dns_question(domain_parts, query_type)
    print(dns_question)

    return dns_header + dns_question + get_dns_body(*record_info)








if __name__ == '__main__':
    ip, port = '127.0.0.1', 53

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((ip, port))

    while 1:
        # dns specification says that udp should be used for packets sz <= 512 bytes (octets)
        query, addr = sock.recvfrom(512)
        print(query)
        print(type(query))
        print()

        r = response(query)
        sock.sendto(r, addr)

