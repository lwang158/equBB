#!/usr/bin/python
"""Given two basic blocks, compare the equivalence of them. 
Li Wang, 07-24-2018. 
For any question please contact lzw158@ist.psu.edu"""

import angr,monkeyhex

proj = angr.Project('./intsum')

print proj.arch
print proj.filename
print hex(proj.entry)
print proj.loader
print proj.loader.main_object


#locate the information of the given symbol name, which includes the address of the symbol
symbolinfo = proj.loader.find_symbol('intsum')
print hex(symbolinfo.rebased_addr)

#locate the basic block which contains the address parameter
#block = proj.factory.block(0x40052d)
block = proj.factory.block(symbolinfo.rebased_addr)
block.pp()

state = proj.factory.entry_state()
