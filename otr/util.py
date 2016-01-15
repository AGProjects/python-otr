
from application.python.types import MarkerType
from binascii import a2b_hex as hex_decode, b2a_hex as hex_encode
from struct import Struct, pack


__all__ = ('Data', 'MPI', 'bytes_to_long', 'long_to_bytes', 'pack_data', 'pack_mpi', 'read_format', 'read_data', 'read_mpi', 'read_content')


class Data: __metaclass__ = MarkerType
class MPI:  __metaclass__ = MarkerType


def bytes_to_long(string):
    return int(hex_encode(string), 16)


def long_to_bytes(number, length=1):
    hex_str = '{:0{}x}'.format(number, length*2)
    if len(hex_str) % 2:
        hex_str = '0' + hex_str
    return hex_decode(hex_str)


def pack_data(data):
    return pack('!I', len(data)) + data


def pack_mpi(mpi):
    return pack_data(long_to_bytes(mpi))


def read_format(format, buffer, offset=0):
    data_structure = Struct(format)
    if len(buffer) < offset + data_structure.size:
        raise ValueError("Not enough data bytes in message")
    return data_structure.unpack_from(buffer, offset) + (buffer[offset+data_structure.size:],)


def read_data(buffer, offset=0):
    length, data = read_format('!I', buffer, offset)
    if len(data) < length:
        raise ValueError("Not enough data bytes in message")
    return data[:length], data[length:]


def read_mpi(buffer, offset=0):
    mpi_string, rest = read_data(buffer, offset)
    return bytes_to_long(mpi_string), rest


def read_content(buffer, *elements):
    result = []
    for element in elements:
        if element is MPI:
            mpi, buffer = read_mpi(buffer)
            result.append(mpi)
        elif element is Data:
            data, buffer = read_data(buffer)
            result.append(data)
        elif isinstance(element, bytes):
            output = read_format(element, buffer)
            result.extend(output[:-1])
            buffer = output[-1]
        else:
            raise TypeError("invalid element type: %r" % element)
    return result[0] if len(result) == 1 else tuple(result) or None

