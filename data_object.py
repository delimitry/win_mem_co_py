#!/usr/bin/env python
# -*- coding: utf-8 -*-
#-----------------------------------------------------------------------
# Author: delimitry
#-----------------------------------------------------------------------

import types
import ctypes
import struct
import platform

ReadProcessMemory = ctypes.windll.kernel32.ReadProcessMemory

is_x64 = platform.architecture()[0] == '64bit'

ptr_size = struct.calcsize('P')
int_size = struct.calcsize('i')
short_size = struct.calcsize('h')
long_size = 8 if is_x64 else int_size
double_size = struct.calcsize('d')
wchar_size = ctypes.sizeof(ctypes.c_wchar)

if is_x64:
    SHIFT = 30
    digit_size = int_size
else:
    SHIFT = 15
    digit_size = short_size

BASE = 1 << SHIFT
MASK = BASE - 1

# print 'ptr_size = %d' % ptr_size
# print 'int_size = %d' % int_size
# print 'long_size = %d' % long_size
# print 'short_size = %d' % short_size
# print 'double_size = %d' % double_size
# print 'wchar_size = %d' % wchar_size

marshal_types = {
    id(None):       'N',
    id(int):        'i',
    id(long):       'l',
    id(float):      'g',
    id(complex):    'c',
    id(str):        's',
    id(unicode):    'u',
    id(list):       '[',
    id(tuple):      '(',
    id(dict):       '{',
    id(set):        '<',
    id(frozenset):  '?',
}


def get_python_type(type_value):
    """
    Get python type by type_value
    """
    python_types_dict = {id(getattr(types, t)): ('<%s>' % t) for t in dir(types) if not t.startswith('_')}
    if type_value in python_types_dict:
        return python_types_dict.get(type_value, 'UnknownType')
    return 'UnknownType'


def get_memory(process_handle, base_address, size):
    """
    Get `size` bytes of memory start from `base_address` of process with `process_handle`
    """
    buf_data = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t()
    result = ReadProcessMemory(process_handle, base_address, buf_data, size, ctypes.byref(bytes_read))
    if result:
        return buf_data
    return None


# packers
def pack_int64(data):
    return struct.pack('q', data)


def pack_int(data):
    return struct.pack('i', data)


def pack_uint(data):
    return struct.pack('I', data)


# unpackers
def unpack_int(data):
    return struct.unpack('i', data)[0]


def unpack_uint(data):
    return struct.unpack('I', data)[0]


def unpack_double(data):
    return struct.unpack('d', data)[0]


def unpack_long(data):
    return struct.unpack('q', data)[0] if is_x64 else struct.unpack('i', data)[0]


def unpack_ulong(data):
    return struct.unpack('Q', data)[0] if is_x64 else struct.unpack('I', data)[0]


def unpack_short(data):
    return struct.unpack('H', data)[0]


def unpack_ushort(data):
    return struct.unpack('h', data)[0]


def unpack_addr(data):
    return unpack_ulong(data)


def unpack_bytes(data):
    size = len(data)
    return struct.unpack('%dB' % size, data)


class DataObject(object):
    """
    Data structure
    """

    def __init__(self, data):
        self.data = data
        self.size = 0
        if data:
            self.size = len(data)
        self.offset = 0

    def read(self, bytes_num=-1):
        if not self.data:
            return None
        if bytes_num <= 0:
            res = self.data[self.offset:]
            self.offset = self.size
            return res
        if self.offset + bytes_num > self.size:
            raise Exception('Trying to read more bytes than available! Available %d bytes.' % (self.size - self.offset))
        res_data = self.data[self.offset:self.offset + bytes_num]
        self.offset += bytes_num
        return res_data

    def get_full_data_size(self):
        return self.size

    def get_offset(self):
        return self.offset

    def set_offset(self, value):
        self.offset = value

    def get_full_data(self):
        return self.data

    def get_offset_data(self):
        if not self.data:
            return None
        return self.data[self.offset:]

    # read types
    def read_int(self):
        return self.read(int_size)

    def read_long(self):
        return self.read(long_size)

    def read_double(self):
        return self.read(double_size)

    def read_address(self):
        return self.read(ptr_size)

    # read types unpacked
    def read_int_unpacked(self):
        return unpack_int(self.read_int())

    def read_long_unpacked(self):
        return unpack_long(self.read_long())

    def read_ulong_unpacked(self):
        return unpack_ulong(self.read_long())

    def read_addr_unpacked(self):
        return unpack_addr(self.read_address())

    def read_double_unpacked(self):
        return unpack_double(self.read_double())


def test():
    size = int_size + long_size + ptr_size
    mem_data = DataObject(''.join(chr(i) for i in xrange(size)))
    print hex(mem_data.read_int_unpacked())
    print hex(mem_data.read_long_unpacked())
    print hex(mem_data.read_addr_unpacked())
    #print unpack_int(mem_data.read_int()) # this will failed

if __name__ == '__main__':
    #test()
    pass
