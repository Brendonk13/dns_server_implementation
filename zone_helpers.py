from pathlib import Path
from json import load
from data.prog_data import ENDIAN, QUERY_TYPES

def load_zone_data():
    json_zones = {}
    for zone in Path('data/zones').glob('*zone'):
        with open(zone) as zone_file:
            data = load(zone_file)
            zone_name = data["$origin"]
            json_zones[zone_name] = data
    return json_zones


def get_zone(domain):
    zone_name = '.'.join(domain) + '.'
    zone_data = load_zone_data()
    if zone_name not in zone_data:
        raise ValueError("This DNS server is not aware of the requested domain")
    return zone_data[zone_name]


def extract_queried_domain(query_question):
    seen_chars = 0
    query_type_pos = 1
    expected_len = 0
    domain_part = ''
    domain_parts = []
    new_byte = True
    for byte in query_question:
        query_type_pos += 1
        if new_byte:
            new_byte = False
            expected_len = byte
            continue

        if byte != 0: # dont add the last byte: \x00 to domain_part
            domain_part += chr(byte)
        seen_chars += 1

        if seen_chars == expected_len:
            domain_parts.append(domain_part)
            domain_part = ''
            seen_chars = 0
            new_byte = True
        if byte == 0:
            break

    query_type_code = query_question[query_type_pos-2: query_type_pos]

    return domain_parts, query_type_code


def query_type_string(query_type_code):
    for q_type, q_code in QUERY_TYPES.items():
        if q_code == query_type_code:
            return q_type
            # print(f'query type from question is: {query_type}')
    # Note: this never raised since non-existant
    raise ValueError("Bad DNS request: query type value (QTYPE) not part of the specification")


def queried_records(query_question):
    domain, query_type_code = extract_queried_domain(query_question)
    # convert query_type_code to a string to enhance readability when doing
    # things conditionally based on the value of query_type
    query_type = query_type_string(int.from_bytes(query_type_code, ENDIAN))
    zone = get_zone(domain)

    # Ideally shouldnt be an error which stops the server but oh well
    if query_type not in zone:
        raise ValueError("The requested domain does not have this type of record.")
    return zone[query_type], query_type, domain

