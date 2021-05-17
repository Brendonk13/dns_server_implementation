from functools import reduce
from operator import add
from data.prog_data import ENDIAN



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


