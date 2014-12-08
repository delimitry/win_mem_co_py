memory co py
============

Tool for searching Python structures in memory (Code Objects and Frame Objects).

Name is from russian word: копай (ko-pie) which means dig (imperative form).

Python bytecode is decompiled using **uncompyle2** Python bytecode decompiler, written in Python 2.7.

Usage:
------
The usage of `memory_digger.py` is very simple:
```
usage: memory_digger.py [-h] [-p [PIDS [PIDS ...]]] [-f] [-c] [-s] [-d]
                        [-o [OUTPUT]]

Tool for searching Python structures in memory.

optional arguments:
  -h, --help            show this help message and exit
  -p [PIDS [PIDS ...]], --pids [PIDS [PIDS ...]]
                        Process IDs to search (default: all "python.exe"
                        processes)
  -f, --frames          Search Python Frame Objects (default: disabled)
  -c, --code            Search Python Code Objects (default: disabled)
  -s, --structure       Print Python Objects structure (default: enabled)
  -d, --decompile       Show decompiled code (default: enabled)
  -o [OUTPUT], --output [OUTPUT]
                        File to save
```

Example:
```
memory_digger.py -p 8136 -c -f -o output.txt
```

License:
--------
Released under The MIT License.
