#!/usr/bin/env python
#-*- coding: utf-8 -*-
#-----------------------------------------------------------------------
# Author: delimitry
#-----------------------------------------------------------------------

import sys
import types
import ctypes
import marshal
from data_object import (
    get_memory, get_python_type, DataObject,
    ptr_size, int_size, long_size, double_size, wchar_size, digit_size, SHIFT, marshal_types,
    unpack_uint, unpack_ushort, is_x64
)


Py_TRACE_REFS = hasattr(sys, 'getobjects')
PyDict_MINSIZE = 8
CO_MAXBLOCKS = 20


class VarObject:
    """
    Py Var Object
    """
    ob_size = 0L


class HeadObject:
    """
    Py Head Object
    """
    if Py_TRACE_REFS:
        _ob_next = None
        _ob_prev = None
    ob_refcnt = 0L
    ob_type = None


class VarHeadObject:
    """
    Py Var Head Object
    """
    if Py_TRACE_REFS:
        _ob_next = None
        _ob_prev = None
    ob_refcnt = 0L
    ob_type = None
    ob_size = 0L


class IntObject:
    """
    Python Int Object
    """
    ob_refcnt = 0L
    ob_type = None
    ob_ival = 0


class LongObject:
    """
    Python Long Object
    """
    ob_refcnt = 0L
    ob_type = None
    ob_size = 0L
    ob_value = 0


class FloatObject:
    """
    Python Float Object
    """
    ob_refcnt = 0L
    ob_type = None
    ob_fval = 0.0


class ComplexObject:
    """
    Python Complex Object
    """
    ob_refcnt = 0L
    ob_type = None
    ob_cval_real = 0.0
    ob_cval_imag = 0.0


class StringObject:
    """
    Python String Object
    """
    # var head
    ob_refcnt = 0L
    ob_type = None
    ob_size = 0L
    # vars
    ob_shash = 0L  # the hash of the string is -1 (0xffffffff) if not computed yet
    ob_sstate = 0
    ob_sval = ''

    @staticmethod
    def get_string_state(ob_sstate):
        sstates = {
            0: 'SSTATE_NOT_INTERNED',
            1: 'SSTATE_INTERNED_MORTAL',
            2: 'SSTATE_INTERNED_IMMORTAL',
        }
        return sstates[ob_sstate]


class UnicodeObject:
    """
    Python Unicode Object
    """
    # head
    ob_refcnt = 0L
    ob_type = None
    # vars
    ob_length = 0L
    ob_str = u''
    ob_hash = 0L  # hash is -1 if not set
    ob_defenc = None  # string, or NULL; this is used for implementing the buffer protocol


class TupleObject:
    """
    Python Tuple Object
    """
    # var head
    ob_refcnt = 0L
    ob_type = None
    ob_size = 0L
    # vars
    ob_items = None


class ListObject:
    """
    Python List Object
    """
    # var head
    ob_refcnt = 0L
    ob_type = None
    ob_size = 0L
    # vars
    ob_items = None  # **ob_item
    ob_allocated = 0L


class DictObject:
    """
    Python Dict Object (for Python 2.7)
    """
    # head
    ob_refcnt = 0L
    ob_type = None
    # vars
    ma_fill = 0L  # Active + # Dummy
    ma_used = 0L  # Active
    ma_mask = 0L  # table contains ma_mask + 1 slots, and that's a power of 2
    ma_table = None  # ma_table points to ma_smalltable for small tables, else to additional malloc'ed memory
    ma_lookup = None  # *(*ma_lookup)(PyDictObject *mp, PyObject *key, long hash)
    ma_smalltable = None  # ma_smalltable[PyDict_MINSIZE]
    # own variable
    ob_dict = {}


class DictEntry:
    """
    Python DictEntry Object (for Python 2.7)
    """
    me_hash = 0L
    me_key = None
    me_value = None


class ModuleObject:
    """
    Python Module Object
    """
    # head
    ob_refcnt = 0L
    ob_type = None
    # vars
    md_dict = None


class TryBlock:
    """
    Python TryBlock
    """
    b_type = 0  # what kind of block this is
    b_handler = 0  # where to jump to find handler
    b_level = 0  # value stack level to pop to


class FrameObject:
    """
    Python Frame Object
    """
    # var head
    ob_refcnt = 0L
    ob_type = None
    ob_size = 0L
    # vars
    f_back = None  # previous frame, or NULL
    f_code = None  # code
    f_builtins = None  # builtin symbol table (PyDictObject)
    f_globals = None  # global symbol table (PyDictObject)
    f_locals = None  # local symbol table (any mapping)
    f_valuestack = None  # points after the last local
    f_stacktop = None
    f_trace = None  # trace func
    f_exc_type = None
    f_exc_value = None
    f_exc_traceback = None
    f_gen = None
    f_lasti = 0  # last instruction if called
    f_lineno = 0  # current line number (valid when f_trace is set)
    f_iblock = 0  # index in f_blockstack
    f_executing = 0  # whether the frame is still executing
    f_blockstack = None  # for try and loop blocks, size = CO_MAXBLOCKS
    f_localsplus = None  # locals+stack, dynamically sized


class CodeObject:
    """
    Python Code Object
    """
    # head
    ob_refcnt = 0L
    ob_type = None
    # vars
    co_argcount = 0
    co_nlocals = 0
    co_stacksize = 0
    co_flags = 0
    co_code = None
    co_consts = None
    co_names = None
    co_varnames = None
    co_freevars = None
    co_cellvars = None
    co_filename = ''
    co_name = ''
    co_firstlineno = 0
    co_lnotab = ''
    co_zombieframe = None

    ob_code = None

    @staticmethod
    def get_co_flags(co_flags):
        co_flags_masks = {
            0x00001: 'CO_OPTIMIZED',
            0x00002: 'CO_NEWLOCALS',
            0x00004: 'CO_VARARGS',
            0x00008: 'CO_VARKEYWORDS',
            0x00010: 'CO_NESTED',
            0x00020: 'CO_GENERATOR',
            0x00040: 'CO_NOFREE',  # flag is set if there are no free or cell variables
            0x01000: 'CO_GENERATOR_ALLOWED',  # no longer used
            0x02000: 'CO_FUTURE_DIVISION',
            0x04000: 'CO_FUTURE_ABSOLUTE_IMPORT',
            0x08000: 'CO_FUTURE_WITH_STATEMENT',
            0x10000: 'CO_FUTURE_PRINT_FUNCTION',
            0x20000: 'CO_FUTURE_UNICODE_LITERALS',
        }
        flags_list = []
        for mask in sorted(co_flags_masks.keys()):
            if co_flags & mask == mask:
                flags_list.append(co_flags_masks[mask])
        return flags_list


def get_object(process_handle, address):
    """
    Read memory data to TupleObject
    """
    head_size = long_size * 2
    data_object = DataObject(get_memory(process_handle, address, head_size))
    if data_object.get_full_data():
        ob_refcnt = data_object.read_long_unpacked() & 0xffffffff
        ob_type = data_object.read_long_unpacked() & 0xffffffff
        if ob_type == id(str):
            return get_string_object(process_handle, address)
        elif ob_type == id(unicode):
            return get_unicode_object(process_handle, address)
        elif ob_type == id(int):
            return get_int_object(process_handle, address)
        elif ob_type == id(long):
            return get_long_object(process_handle, address)
        elif ob_type == id(float):
            return get_float_object(process_handle, address)
        elif ob_type == id(complex):
            return get_complex_object(process_handle, address)
        elif ob_type == id(tuple):
            return get_tuple_object(process_handle, address)
        elif ob_type == id(dict):
            return get_dict_object(process_handle, address)
        elif ob_type == id(types.CodeType):
            return get_code_object(process_handle, address)
        elif ob_type == id(type(None)):
            return None
        else:
            return '%s [0x%08x] at "0x%08x"' % (get_python_type(ob_type), ob_type, address)
    raise Exception('Failed to read memory with information about object at "0x%08x"' % address)


def get_int_object(process_handle, address):
    """
    Read memory data to IntObject
    """
    int_object = IntObject()
    data_object = DataObject(get_memory(process_handle, address, long_size * 3))
    int_object.ob_refcnt = data_object.read_long_unpacked() & 0xffffffff
    int_object.ob_type = data_object.read_long_unpacked() & 0xffffffff
    if int_object.ob_type != id(int):
        raise Exception('Invalid IntObject type "0x%08x". Must be "0x%08x"' % (int_object.ob_type, id(int)))
    int_object.ob_ival = ctypes.c_int(data_object.read_long_unpacked() & 0xffffffff).value
    # s, n = int_object.ob_ival >> 31, int_object.ob_ival & 0x7fffffff
    # print n if not s else -0x80000000 + n
    return int_object


def get_long_object(process_handle, address):
    """
    Read memory data to LongObject
    """
    long_object = LongObject()
    size = long_size * 3
    data_object = DataObject(get_memory(process_handle, address, size))
    long_object.ob_refcnt = data_object.read_long_unpacked() & 0xffffffff
    long_object.ob_type = data_object.read_long_unpacked() & 0xffffffff
    if long_object.ob_type != id(long):
        raise Exception('Invalid LongObject type "0x%08x". Must be "0x%08x"' % (long_object.ob_type, id(long)))
    long_object.ob_size = data_object.read_long_unpacked()
    if long_object.ob_size == 0:
        return 0L
    long_object_data = DataObject(get_memory(process_handle, address + size, abs(long_object.ob_size) * digit_size))
    data = long_object_data.read()
    digits = []
    for i in xrange(0, abs(long_object.ob_size)):
        if is_x64:
            digits.append(unpack_uint(data[i * digit_size: i * digit_size + digit_size]))
        else:
            digits.append(unpack_ushort(data[i * digit_size: i * digit_size + digit_size]))
    value = 0L
    for i in xrange(0, abs(long_object.ob_size)):
        value += digits[i] * 2 ** (SHIFT * i)
    if long_object.ob_size < 0:
        value = -value
    long_object.ob_value = value
    return long_object


def get_float_object(process_handle, address):
    """
    Read memory data to FloatObject
    """
    float_object = FloatObject()
    size = long_size * 2 + double_size
    data_object = DataObject(get_memory(process_handle, address, size))
    float_object.ob_refcnt = data_object.read_long_unpacked() & 0xffffffff
    float_object.ob_type = data_object.read_long_unpacked() & 0xffffffff
    if float_object.ob_type != id(float):
        raise Exception('Invalid FloatObject type "0x%08x". Must be "0x%08x"' % (float_object.ob_type, id(float)))
    data = data_object.read(double_size)
    value = marshal.loads(marshal_types[float_object.ob_type] + data)
    float_object.ob_fval = value
    return float_object


def get_complex_object(process_handle, address):
    """
    Read memory data to ComplexObject
    """
    complex_object = ComplexObject()
    size = long_size * 2 + double_size * 2
    data_object = DataObject(get_memory(process_handle, address, size))
    complex_object.ob_refcnt = data_object.read_long_unpacked() & 0xffffffff
    complex_object.ob_type = data_object.read_long_unpacked() & 0xffffffff
    if complex_object.ob_type != id(complex):
        raise Exception('Invalid ComplexObject type "0x%08x". Must be "0x%08x"' % (complex_object.ob_type, id(complex)))
    complex_object.ob_cval_real = data_object.read_double_unpacked()
    complex_object.ob_cval_imag = data_object.read_double_unpacked()
    return complex_object


def get_tuple_object(process_handle, address):
    """
    Read memory data to TupleObject
    """
    tuple_object = TupleObject()
    size = long_size * 3
    data_object = DataObject(get_memory(process_handle, address, size))
    tuple_object.ob_refcnt = data_object.read_long_unpacked() & 0xffffffff
    tuple_object.ob_type = data_object.read_long_unpacked() & 0xffffffff
    if tuple_object.ob_type != id(tuple):
        raise Exception('Invalid TupleObject type "0x%08x". Must be "0x%08x"' % (tuple_object.ob_type, id(tuple)))
    tuple_object.ob_size = data_object.read_long_unpacked() & 0xffffffff
    items_data_object = DataObject(get_memory(process_handle, address + size, tuple_object.ob_size * ptr_size))
    items = []
    for _ in xrange(0, tuple_object.ob_size):
        item_addr = items_data_object.read_addr_unpacked()
        if item_addr == id(None):
            items.append(None)
        else:
            item_value = get_object(process_handle, item_addr)
            if isinstance(item_value, StringObject):
                items.append(item_value.ob_sval)
            elif isinstance(item_value, UnicodeObject):
                items.append(item_value.ob_str)
            elif isinstance(item_value, IntObject):
                items.append(item_value.ob_ival)
            elif isinstance(item_value, LongObject):
                items.append(item_value.ob_value)
            elif isinstance(item_value, FloatObject):
                items.append(item_value.ob_fval)
            elif isinstance(item_value, ComplexObject):
                items.append(complex(item_value.ob_cval_real, item_value.ob_cval_imag))
            elif isinstance(item_value, TupleObject):
                items.append(tuple(item_value.ob_items))
            elif isinstance(item_value, DictObject):
                items.append(dict(item_value.ob_dict))
            elif isinstance(item_value, CodeObject):
                items.append(item_value.ob_code)
            else:
                items.append(item_value)
    tuple_object.ob_items = items
    return tuple_object


def get_dict_entry(process_handle, address):
    """
    Read memory to DictEntry object
    """
    dict_entry = DictEntry()
    size = long_size + ptr_size * 2
    data_object = DataObject(get_memory(process_handle, address, size))
    dict_entry.me_hash = data_object.read_long_unpacked()
    dict_entry.me_key = get_object(process_handle, data_object.read_addr_unpacked())
    dict_entry.me_value = get_object(process_handle, data_object.read_addr_unpacked())
    return dict_entry


def get_dict_object(process_handle, address):
    """
    Read memory to DictObject
    """
    dict_object = DictObject()
    head_size = long_size * 2
    head_data_object = DataObject(get_memory(process_handle, address, head_size))
    dict_object.ob_refcnt = head_data_object.read_long_unpacked() & 0xffffffff
    dict_object.ob_type = head_data_object.read_long_unpacked() & 0xffffffff
    if dict_object.ob_type != id(dict):
        raise Exception('Invalid DictObject type "0x%08x". Must be "0x%08x"' % (dict_object.ob_type, id(dict)))
    # read fields
    size = long_size * 3 + ptr_size * 2
    data_object = DataObject(get_memory(process_handle, address + head_size, size))
    dict_object.ma_fill = data_object.read_long_unpacked() & 0xffffffff
    dict_object.ma_used = data_object.read_long_unpacked() & 0xffffffff
    dict_object.ma_mask = data_object.read_long_unpacked() & 0xffffffff
    dict_object.ma_table = data_object.read_addr_unpacked()
    dict_object.ma_lookup = data_object.read_addr_unpacked()
    # get dict entries from ma_smalltable
    dict_entry_size = long_size + ptr_size * 2
    st_dict_entries = []
    for i in xrange(PyDict_MINSIZE):
        try:
            st_dict_entry = get_dict_entry(process_handle, address + head_size + size + dict_entry_size * i)
            st_dict_entries.append(st_dict_entry)
        except:
            pass
    dict_object.ma_smalltable = st_dict_entries
    # get dict entries from ma_table
    t_dict_entries = []
    if dict_object.ma_fill > PyDict_MINSIZE:
        for i in xrange(dict_object.ma_fill - PyDict_MINSIZE):
            try:
                t_dict_entry = get_dict_entry(process_handle, dict_object.ma_table + dict_entry_size * i)
                t_dict_entries.append(t_dict_entry)
            except:
                pass
    full_dict = {}
    for dict_item in st_dict_entries + t_dict_entries:
        if dict_item and dict_item.me_key:
            #print dict_item.me_key, dict_item.me_value
            k = get_object_value(dict_item.me_key)
            v = get_object_value(dict_item.me_value)
            if k:
                full_dict[k] = v
    dict_object.ob_dict = full_dict
    return dict_object


def get_string_object(process_handle, address):
    """
    Read memory to StringObject
    """
    string_object = StringObject()
    size = long_size * 3 + int_size * 2
    data_object = DataObject(get_memory(process_handle, address, size))
    if data_object.get_full_data_size() < size:
        raise Exception('Invalid size of StringObject type')
    string_object.ob_refcnt = data_object.read_long_unpacked() & 0xffffffff
    string_object.ob_type = data_object.read_long_unpacked() & 0xffffffff
    if string_object.ob_type != id(str):
        raise Exception('Invalid StringObject type "0x%08x". Must be "0x%08x"' % (string_object.ob_type, id(str)))
    string_object.ob_size = data_object.read_long_unpacked() & 0xffffffff
    string_object.ob_shash = data_object.read_int_unpacked() & 0xffffffff
    string_object.ob_sstate = data_object.read_int_unpacked() & 0xffffffff
    string_data_object = DataObject(get_memory(process_handle, address + size, string_object.ob_size))
    string_object.ob_sval = string_data_object.read(string_object.ob_size)
    return string_object


def get_unicode_object(process_handle, address):
    """
    Read memory to UnicodeObject
    """
    unicode_object = UnicodeObject()
    size = long_size * 3 + int_size + ptr_size * 2
    data_object = DataObject(get_memory(process_handle, address, size))
    if data_object.get_full_data_size() < size:
        raise Exception('Invalid size of UnicodeObject type')
    unicode_object.ob_refcnt = data_object.read_long_unpacked() & 0xffffffff
    unicode_object.ob_type = data_object.read_long_unpacked() & 0xffffffff
    if unicode_object.ob_type != id(str):
        raise Exception('Invalid UnicodeObject type "0x%08x". Must be "0x%08x"' % (unicode_object.ob_type, id(unicode)))
    unicode_object.ob_length = data_object.read_long_unpacked() & 0xffffffff
    unicode_data_object = DataObject(
        get_memory(process_handle, data_object.read_addr_unpacked(), unicode_object.ob_length * wchar_size))
    unicode_object.ob_str = unicode_data_object.read(unicode_object.ob_length * wchar_size).decode('utf-16le')
    unicode_object.ob_hash = data_object.read_int_unpacked() & 0xffffffff
    unicode_object.defenc = data_object.read_addr_unpacked()
    return unicode_object


def get_module_object(process_handle, address):
    """
    Read memory to ModuleObject
    """
    module_object = ModuleObject()
    size = long_size * 3
    data_object = DataObject(get_memory(process_handle, address, size))
    if data_object.get_full_data_size() < size:
        raise Exception('Invalid size of ModuleObject type')
    module_object.ob_refcnt = data_object.read_long_unpacked() & 0xffffffff
    module_object.ob_type = data_object.read_long_unpacked() & 0xffffffff
    if module_object.ob_type != id(types.ModuleType):
        raise Exception(
            'Invalid ModuleObject type "0x%08x". Must be "0x%08x"' % (module_object.ob_type, id(types.ModuleType)))
    module_object.md_dict = get_dict_object(process_handle, data_object.read_addr_unpacked())
    return module_object


def get_code_object(process_handle, address):
    """
    Read memory to CodeObject
    """
    code_object = CodeObject()
    size = long_size * 3 + int_size * 4 + ptr_size * 10
    data_object = DataObject(get_memory(process_handle, address, size))
    code_object.ob_refcnt = data_object.read_long_unpacked() & 0xffffffff
    code_object.ob_type = data_object.read_long_unpacked() & 0xffffffff
    if code_object.ob_type != id(types.CodeType):
        raise Exception(
            'Invalid CodeObject type "0x%08x". Must be "0x%08x"' % (code_object.ob_type, id(types.CodeType)))
    code_object.co_argcount = data_object.read_int_unpacked() & 0xffffffff
    code_object.co_nlocals = data_object.read_int_unpacked() & 0xffffffff
    code_object.co_stacksize = data_object.read_int_unpacked() & 0xffffffff
    code_object.co_flags = data_object.read_int_unpacked() & 0xffffffff
    code_object.co_code = get_string_object(process_handle, data_object.read_addr_unpacked())
    code_object.co_consts = get_tuple_object(process_handle, data_object.read_addr_unpacked())
    code_object.co_names = get_tuple_object(process_handle, data_object.read_addr_unpacked())
    code_object.co_varnames = get_tuple_object(process_handle, data_object.read_addr_unpacked())
    code_object.co_freevars = get_tuple_object(process_handle, data_object.read_addr_unpacked())
    code_object.co_cellvars = get_tuple_object(process_handle, data_object.read_addr_unpacked())
    code_object.co_filename = get_string_object(process_handle, data_object.read_addr_unpacked())
    code_object.co_name = get_string_object(process_handle, data_object.read_addr_unpacked())
    code_object.co_firstlineno = data_object.read_ulong_unpacked() & 0xffffffff
    code_object.co_lnotab = get_string_object(process_handle, data_object.read_addr_unpacked())
    code_object.co_zombieframe = data_object.read_addr_unpacked()
    # fill ob_code
    code_object.ob_code = types.CodeType(
        code_object.co_argcount,
        code_object.co_nlocals,
        code_object.co_stacksize,
        code_object.co_flags,
        code_object.co_code.ob_sval,
        tuple(code_object.co_consts.ob_items),
        tuple(code_object.co_names.ob_items),
        tuple(code_object.co_varnames.ob_items),
        code_object.co_filename.ob_sval,
        code_object.co_name.ob_sval,
        code_object.co_firstlineno,
        code_object.co_lnotab.ob_sval,
        tuple(code_object.co_freevars.ob_items),
        tuple(code_object.co_cellvars.ob_items)
    )
    return code_object


def get_try_block(process_handle, address):
    """
    Read memory to TryBlock
    """
    try_block = TryBlock()
    size = int_size * 3
    data_object = DataObject(get_memory(process_handle, address, size))
    try_block.b_type = data_object.read_int_unpacked()
    try_block.b_handler = data_object.read_int_unpacked()
    try_block.b_level = data_object.read_int_unpacked()
    return try_block


def get_frame_object(process_handle, address):
    """
    Read memory to FrameObject
    """
    frame_object = FrameObject()
    size = long_size * 3
    var_head_data_object = DataObject(get_memory(process_handle, address, size))
    frame_object.ob_refcnt = var_head_data_object.read_long_unpacked() & 0xffffffff
    frame_object.ob_type = var_head_data_object.read_long_unpacked() & 0xffffffff
    if frame_object.ob_type != id(types.FrameType):
        raise Exception(
            'Invalid FrameObject type "0x%08x". Must be "0x%08x"' % (frame_object.ob_type, id(types.FrameType)))
    frame_object.ob_size = var_head_data_object.read_long_unpacked() & 0xffffffff
    vars_size = ptr_size * 12 + int_size * 4
    data_object = DataObject(get_memory(process_handle, address + size, vars_size))
    frame_object.f_back = data_object.read_addr_unpacked()
    frame_object.f_code = get_code_object(process_handle, data_object.read_addr_unpacked())
    frame_object.f_builtins = get_dict_object(process_handle, data_object.read_addr_unpacked())
    frame_object.f_globals = get_dict_object(process_handle, data_object.read_addr_unpacked())
    frame_object.f_locals = data_object.read_addr_unpacked()
    frame_object.f_valuestack = data_object.read_addr_unpacked()
    frame_object.f_stacktop = data_object.read_addr_unpacked()
    frame_object.f_trace = data_object.read_addr_unpacked()
    frame_object.f_exc_type = data_object.read_addr_unpacked()
    frame_object.f_exc_value = data_object.read_addr_unpacked()
    frame_object.f_exc_traceback = data_object.read_addr_unpacked()
    frame_object.f_gen = data_object.read_addr_unpacked()
    frame_object.f_lasti = data_object.read_int_unpacked() & 0xffffffff
    frame_object.f_lineno = data_object.read_int_unpacked() & 0xffffffff
    frame_object.f_iblock = data_object.read_int_unpacked() & 0xffffffff
    frame_object.f_executing = data_object.read_int_unpacked() & 0xffffffff
    try_blocks = []
    for i in xrange(CO_MAXBLOCKS):
        try_block_address = address + size + vars_size + int_size * 3 * i
        try_blocks.append(get_try_block(process_handle, try_block_address))
    frame_object.f_blockstack = try_blocks
    data_object = DataObject(get_memory(process_handle, address + size + vars_size + int_size * 3 * CO_MAXBLOCKS, ptr_size))
    frame_object.f_localsplus = data_object.read_addr_unpacked()
    return frame_object


def get_object_value(obj):
    """
    Return object `obj` value
    """
    if isinstance(obj, StringObject):
        return obj.ob_sval
    elif isinstance(obj, UnicodeObject):
        return obj.ob_str
    elif isinstance(obj, IntObject):
        return obj.ob_ival
    elif isinstance(obj, LongObject):
        return obj.ob_value
    elif isinstance(obj, FloatObject):
        return obj.ob_fval
    elif isinstance(obj, ComplexObject):
        return complex(obj.ob_cval_real, obj.ob_cval_imag)
    elif isinstance(obj, TupleObject):
        return tuple(obj.ob_items)
    elif isinstance(obj, DictObject):
        return dict(obj.ob_dict)
    elif isinstance(obj, CodeObject):
        return obj.ob_code
    return obj

