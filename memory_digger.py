#!/usr/bin/env python
#-*- coding: utf-8 -*-
#-----------------------------------------------------------------------
# Author: delimitry
#-----------------------------------------------------------------------

import sys
import types
import ctypes
from ctypes import windll
from cStringIO import StringIO
from uncompyle2 import walker, scanner27
from data_object import pack_uint, ptr_size, get_python_type
from python_objects import CodeObject, get_frame_object, get_code_object
from frames_sequence import build_frames_sequences

if sys.version_info[0] > 2:
    print 'Python version > 2 is unsupported!'
    sys.exit()

EnumProcesses = windll.psapi.EnumProcesses
OpenProcess = windll.kernel32.OpenProcess
GetCurrentProcessId = windll.kernel32.GetCurrentProcessId
ReadProcessMemory = windll.kernel32.ReadProcessMemory
GetModuleBaseName = windll.psapi.GetModuleBaseNameA
CloseHandle = windll.kernel32.CloseHandle

PROCESS_ALL_ACCESS = 0x1F0FFF
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MAX_PATH = 260


def get_python_pids():
    """
    Return all running "python.exe" processes' PIDs
    """
    from ctypes import wintypes
    python_pids = []
    current_pid = GetCurrentProcessId()
    process_ids = (wintypes.DWORD * 0xffff)()
    cb = ctypes.sizeof(process_ids)
    bytes_returned = wintypes.DWORD()
    res = EnumProcesses(ctypes.byref(process_ids), cb, ctypes.byref(bytes_returned))
    if not res:
        print 'Failed to get processes!'
        return python_pids
    # find all "python.exe" processes
    for index in range(bytes_returned.value / ctypes.sizeof(wintypes.DWORD)):
        pid = process_ids[index]
        h_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if h_process:
            base_name = (ctypes.c_char * MAX_PATH)()
            if GetModuleBaseName(h_process, 0, base_name, MAX_PATH) > 0:
                if base_name.value.lower() == 'python.exe' and pid != current_pid:
                    python_pids.append(pid)
            CloseHandle(h_process)
    return python_pids


def find_pattern_in_process_memory(pattern, pid, read_chunk=0xffff, start_addr=0, end_addr=0x7fffffff):
    """
    Find all offsets/addresses of pattern in PID's memory
    """
    found_addresses = []
    buf = ctypes.create_string_buffer(read_chunk)
    bytes_read = ctypes.c_size_t()
    process_handle = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    # scan memory
    for i in xrange(start_addr, end_addr, read_chunk):
        base_address = i
        res = ReadProcessMemory(process_handle, base_address, buf, read_chunk, ctypes.byref(bytes_read))
        if res:
            pos = 0
            while pos > -1:
                pos = buf.raw.find('%s' % pattern, pos + 1)
                if pos > -1:
                    found_addresses.append(base_address + pos)
    return found_addresses


def decompile_code(code_object):
    """
    Decompile Python code using `uncompyle2` tool.
    """
    # init vars
    co = code_object
    showasm = False
    showast = False
    out = StringIO()
    scanner = scanner27.Scanner27()
    scanner.setShowAsm(showasm, out)
    tokens, customize = scanner.disassemble(co)

    #  Build AST from disassembly.
    walk = walker.Walker(out, scanner, showast=showast)
    try:
        ast = walk.build_ast(tokens, customize)
    except walker.ParserError as ex:  # parser failed, dump disassembly
        print >> out, ex
        raise
    del tokens  # save memory

    # convert leading '__doc__ = "..." into doc string
    assert ast == 'stmts'
    try:
        if ast[0][0] == walker.ASSIGN_DOC_STRING(co.co_consts[0]):
            walk.print_docstring('', co.co_consts[0])
            del ast[0]
        if ast[-1] == walker.RETURN_NONE:
            ast.pop()  # remove last node
        #todo: if empty, add 'pass'
    except:
        pass
    walk.mod_globs = walker.find_globals(ast, set())
    walk.gen_source(ast, customize)
    if walk.ERROR:
        raise Exception(walk.ERROR)
    return out.getvalue()


def find_frame_objects(pids=None, print_struct=True, to_file=False):
    """
    Find all Python Frame Objects in memory
    """
    python_pids = pids if pids else get_python_pids()
    frames = {}
    out_res = ''
    for pid in python_pids:
        print 'scanning PID: %d' % pid
        # prepare frame pattern
        pattern_str = pack_uint(id(types.FrameType))
        found_addresses = find_pattern_in_process_memory(pattern_str, pid)
        print 'found possible addresses:', found_addresses
        frames_num = 0
        if to_file:
            print 'saving frame objects to file...'
        for type_address in found_addresses:
            address = type_address - ptr_size
            try:
                process_handle = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
                f = get_frame_object(process_handle, address)
                frames_num += 1
                struct_res = ''
                struct_res += '# %d frame struct' % frames_num + '\n'
                struct_res += '--------------------------------------------------------------------------------' + '\n'
                struct_res += 'PID: %s | address: 0x%x' % (pid, address) + '\n'
                struct_res += '--------------------------------------------------------------------------------' + '\n'
                struct_res += 'ob_refcnt           | 0x%x' % f.ob_refcnt + '\n'
                struct_res += 'ob_type             | 0x%x' % f.ob_type + ' | ' + get_python_type(f.ob_type) + '\n'
                struct_res += 'ob_size             | 0x%x' % f.ob_size + '\n'
                struct_res += 'f_back              | 0x%x' % f.f_back + '\n'
                struct_res += 'f_code              | %r' % f.f_code + '\n'
                struct_res += 'f_builtins.ob_dict  | %r' % f.f_builtins.ob_dict + '\n'
                struct_res += 'f_globals.ob_dict   | %r' % f.f_globals.ob_dict + '\n'
                struct_res += 'f_locals            | %r' % f.f_locals + '\n'
                struct_res += 'f_valuestack        | 0x%x' % f.f_valuestack + '\n'
                struct_res += 'f_stacktop          | 0x%x' % f.f_stacktop + '\n'
                struct_res += 'f_trace             | 0x%x' % f.f_trace + '\n'
                struct_res += 'f_exc_type          | 0x%x' % f.f_exc_type + '\n'
                struct_res += 'f_exc_value         | 0x%x' % f.f_exc_value + '\n'
                struct_res += 'f_exc_traceback     | 0x%x' % f.f_exc_traceback + '\n'
                struct_res += 'f_gen               | 0x%x' % f.f_gen + '\n'
                struct_res += 'f_lasti             | 0x%x' % f.f_lasti + '\n'
                struct_res += 'f_lineno            | 0x%x' % f.f_lineno + '\n'
                struct_res += 'f_iblock            | 0x%x' % f.f_iblock + '\n'
                struct_res += 'f_executing         | 0x%x' % f.f_executing + '\n'
                struct_res += 'f_blockstack        | %r' % f.f_blockstack + '\n'
                struct_res += 'f_localsplus        | 0x%x' % f.f_localsplus + '\n'
                struct_res += '--------------------------------------------------------------------------------' + '\n'
                if print_struct:
                    if to_file:
                        out_res += struct_res
                    else:
                        print struct_res
                frames[address] = f
            except:
                #import traceback
                #traceback.print_exc()
                pass
    return frames, out_res


def find_code_objects(pids=None, print_struct=True, print_code=True, to_file=False):
    """
    Find all Python Code Objects in memory
    """
    python_pids = pids if pids else get_python_pids()
    code_objects = {}
    out_res = ''
    for pid in python_pids:
        print 'scanning PID: %d' % pid
        # prepare code object pattern
        pattern_str = pack_uint(id(types.CodeType))
        found_addresses = find_pattern_in_process_memory(pattern_str, pid)
        print found_addresses
        code_object = 0
        decompiled_num = 0
        if to_file:
            print 'saving code objects to file...'
        for type_address in found_addresses:
            address = type_address - ptr_size
            try:
                process_handle = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
                c = get_code_object(process_handle, address)
                code_object += 1
                struct_res = ''
                struct_res += '# %d code struct' % code_object + '\n'
                struct_res += '--------------------------------------------------------------------------------' + '\n'
                struct_res += 'PID: %s | address: 0x%x' % (pid, address) + '\n'
                struct_res += '--------------------------------------------------------------------------------' + '\n'
                struct_res += 'ob_refcnt           | 0x%x' % c.ob_refcnt + '\n'
                struct_res += 'ob_type             | 0x%x' % c.ob_type + ' | ' + get_python_type(c.ob_type) + '\n'
                struct_res += 'co_argcount         | 0x%x' % c.co_argcount + '\n'
                struct_res += 'co_nlocals          | 0x%x' % c.co_nlocals + '\n'
                struct_res += 'co_stacksize        | 0x%x' % c.co_stacksize + '\n'
                struct_res += 'co_flags            | 0x%x' % c.co_flags + str(CodeObject.get_co_flags(c.co_flags)) + '\n'
                struct_res += 'co_code.ob_sval     | %r' % c.co_code.ob_sval + '\n'
                struct_res += 'co_consts           | %s' % str(tuple(c.co_consts.ob_items)) + '\n'
                struct_res += 'co_names            | %s' % str(tuple(c.co_names.ob_items)) + '\n'
                struct_res += 'co_varnames         | %s' % str(tuple(c.co_varnames.ob_items)) + '\n'
                struct_res += 'co_freevars         | %s' % str(tuple(c.co_freevars.ob_items)) + '\n'
                struct_res += 'co_cellvars         | %s' % str(tuple(c.co_cellvars.ob_items)) + '\n'
                struct_res += 'co_filename.ob_sval | %r' % c.co_filename.ob_sval + '\n'
                struct_res += 'co_name.ob_sval     | %r' % c.co_name.ob_sval + '\n'
                struct_res += 'co_firstlineno      | 0x%x' % c.co_firstlineno + '\n'
                struct_res += 'co_lnotab.ob_sval   | %r' % c.co_lnotab.ob_sval + '\n'
                struct_res += 'co_zombieframe      | 0x%x' % c.co_zombieframe + '\n'
                struct_res += '--------------------------------------------------------------------------------' + '\n'
                if print_struct:
                    if to_file:
                        out_res += struct_res
                    else:
                        print struct_res

                func_code = types.CodeType(
                    c.co_argcount,
                    c.co_nlocals,
                    c.co_stacksize,
                    c.co_flags,
                    c.co_code.ob_sval,
                    tuple(c.co_consts.ob_items),
                    tuple(c.co_names.ob_items),
                    tuple(c.co_varnames.ob_items),
                    c.co_filename.ob_sval,
                    c.co_name.ob_sval,
                    c.co_firstlineno,
                    c.co_lnotab.ob_sval,
                    tuple(c.co_freevars.ob_items),
                    tuple(c.co_cellvars.ob_items)
                )

                try:
                    dec_code = decompile_code(func_code)
                    decompiled_num += 1
                except KeyboardInterrupt:
                    sys.exit()
                except:
                    #import traceback
                    #traceback.print_exc()
                    pass

                code_res = ''
                code_res += '# %d decompiled' % decompiled_num + '\n'
                code_res += '--------------------------------------------------------------------------------' + '\n'
                args = ', '.join(c.co_varnames.ob_items[:c.co_argcount])
                if 4 & c.co_flags:
                    args += ', *%s' % c.co_varnames.ob_items[c.co_argcount]
                if 8 & c.co_flags:
                    args += ', **%s' % c.co_varnames.ob_items[c.co_argcount + 1]
                code_res += 'Decompiled function "%s(%s)" from "%s":' % (c.co_name.ob_sval, args, c.co_filename.ob_sval) + '\n'
                code_res += '--------------------------------------------------------------------------------' + '\n'
                code_res += dec_code + '\n'
                code_res += '--------------------------------------------------------------------------------' + '\n'
                if print_code:
                    if to_file:
                        out_res += code_res
                    else:
                        print code_res

                code_objects[address] = c
                code_objects[address].dec_code = dec_code
            except KeyboardInterrupt:
                sys.exit()
            except:
                #import traceback
                #traceback.print_exc()
                pass
    return code_objects, out_res


def parse_arguments():
    """ 
    Parse variables from command line 
    """
    import argparse
    parser = argparse.ArgumentParser(description='Tool for searching Python structures in memory.')
    parser.add_argument('-p', '--pids', nargs='*', type=int, default=None, help='Process IDs to search (default: all "python.exe" processes)')
    parser.add_argument('-f', '--frames', action='store_true', help='Search Python Frame Objects (default: disabled)')
    parser.add_argument('-c', '--code', action='store_true', help='Search Python Code Objects (default: disabled)')
    parser.add_argument('-s', '--structure', action='store_false', help='Print Python Objects structure (default: enabled)')
    parser.add_argument('-d', '--decompile', action='store_false', help='Show decompiled code (default: enabled)')
    parser.add_argument('-o', '--output', nargs='?', type=argparse.FileType('ab', 0), help='File to save')
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_arguments()
    to_file = False or args.output
    if args.frames:
        frames_list = []
        frames, out_res = find_frame_objects(pids=args.pids, print_struct=args.structure, to_file=to_file)
        if to_file:
            args.output.write(out_res)
            print 'done'
        for a, f in frames.items():
            frames_list.append((f.f_back, a))            
    if args.code:
        code_objects, out_res = find_code_objects(pids=args.pids, print_struct=args.structure, print_code=args.decompile, to_file=to_file)
        if to_file:
            args.output.write(out_res)
            print 'done'
