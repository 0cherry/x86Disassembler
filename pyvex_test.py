import pyvex
import archinfo

code = '558bec8b45083b450c7e078b4508eb05eb038b450c5dc3'
code = str(bytearray.fromhex(code))
offset = 0x401450

while True:
    irsb = pyvex.lift(code, offset, archinfo.ArchX86())
    print type(irsb)
    irsb.pp()
    next_address = irsb.next.con.value
    # print(type(irsb.next.con.value))
    code = code[(next_address - offset):]
    offset = next_address

# print irsb.next
# print irsb.jumpkind

# print('====================')
# print(type(irsb.next))
# irsb.next.pp()
# irsb = irsb.next

# for stmt in irsb.statements:
#     stmt.pp()
