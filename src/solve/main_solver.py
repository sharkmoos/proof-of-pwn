import logging
import json
from pwn import *
import os
import subprocess

from solvers import LevelZeroSolver, LevelOneSolver, LevelTwoSolver, LevelThreeSolver, LevelFourSolver, submit_stage_code

ip, comms_port, challenge_port = "127.0.0.1", 1337, 9999
stage_code_file = "stage_codes.json"
binary_dir = "binaries"

context.log_level = "INFO"


def collect_flags(stage_codes: dict, r) -> None:
    r.sendline(b"reset")
    pause(1)
    for code in stage_codes:
        r.sendline(code)
        if code == [1, 26, 76, 151, 251]:
            flag = r.recvline_contains(b"cueh", timeout=1).split(b":")[1].strip().decode()
            if len(flag) > 1:
                log.success(f"Flag: {flag}")
            else:
                log.error("Failed to get flag")
        r.clean()


def collect_new_zip(level: str) -> None:
    log.info(f"Collecting {level} zip file")
    sleep(7)
    p = process(["wget", "http://localhost:4750", "-O", f"binaries/{level}.zip"], level="ERROR")
    p.poll(True)
    p = process([f"unzip", f"binaries/{level}.zip", "-d", f"binaries/{level}"], level="ERROR")
    p.poll(True)
    
    #os.remove(f"binaries/{level}.zip")


def submit_already_solved(connection, stage_codes: dict):
    log.info(f"Submitting already solved stage codes ({len(stage_codes.values())} levels)")
    for code in stage_codes.values():
        submit_stage_code(connection, code)
    return


def solve_stage_zero(stage_codes: dict, r) -> bool:
    level_zero_solver = LevelZeroSolver(ip, challenge_port, binary_dir, "./flag.txt", r)

    level_0_challenges = sorted(os.listdir(level_zero_solver.binary_dir))
    for challenge in level_0_challenges:
        if not level_zero_solver.solve_level(os.path.join(level_zero_solver.binary_dir, challenge)):
            log.critical("Failed to solve level 0 challenge: {}".format(challenge))

    for code in level_zero_solver.stage_codes:
        stage_codes[(len(stage_codes))] = code

    if len(level_zero_solver.stage_codes) == len(level_0_challenges):
        log.success("Solved all level 0 challenges")
        return True
    else:
        log.critical("Failed to solve all level 0 challenges")
        return False



def solve_stage_one(stage_codes: dict, r) -> bool:
    """
    Level 1 is actually just more level 0 binaries. So might as well not rewrite that function.
    :param stage_codes:
    :param r:
    :return:
    """
    level_one_solver = LevelOneSolver(ip, challenge_port, binary_dir, "./flag.txt", r)
    level_one_solver.binary_dir = os.path.join(binary_dir, "level_1")

    level_one_challenges = [f for f in os.listdir("binaries/level_1")]
    level_one_challenges.sort(key=lambda f: int(''.join(filter(str.isdigit, f))))

    for challenge in level_one_challenges:
        if not level_one_solver.solve_level(os.path.join(level_one_solver.binary_dir, challenge)):
            log.critical("Failed to solve level 1 challenge: {}".format(challenge))

    for code in level_one_solver.stage_codes:
        stage_codes[(len(stage_codes))] = code

    if len(level_one_solver.stage_codes) == len(level_one_challenges):
        log.success("Solved all level 0 challenges")
        return True
    else:
        log.critical("Failed to solve all level 0 challenges")
        return False


def solve_stage_two(stage_codes: dict, r) -> bool:
    level_two_solver = LevelTwoSolver(ip, challenge_port, binary_dir, "./flag.txt", r)

    level_two_challenges = [f for f in os.listdir("binaries/level_2")]
    level_two_challenges.sort(key=lambda f: int(''.join(filter(str.isdigit, f))))

    for challenge in level_two_challenges:
        if not level_two_solver.solve_level(os.path.join(level_two_solver.binary_dir, challenge)):
            log.critical("Failed to solve level 2 challenge: {}".format(challenge))

    for code in level_two_solver.stage_codes:
        stage_codes[(len(stage_codes))] = code

    if len(level_two_solver.stage_codes) == len(level_two_challenges):
        log.success("Solved all level 2 challenges")
        return True
    else:
        log.critical("Failed to solve all level 2 challenges")
        return False


def solve_stage_three(stage_codes: dict, r) -> bool:
    level_three_solver = LevelThreeSolver(ip, challenge_port, binary_dir, "./flag.txt", r)

    level_three_challenges = [f for f in os.listdir("binaries/level_3")]
    level_three_challenges.sort(key=lambda f: int(''.join(filter(str.isdigit, f))))

    for challenge in level_three_challenges:
        if not level_three_solver.solve_level(os.path.join(level_three_solver.binary_dir, challenge)):
            log.critical("Failed to solve level 3 challenge: {}".format(challenge))
            exit()
        else:
            stage_codes[(len(stage_codes))] = level_three_solver.stage_codes[-1]


    if len(level_three_solver.stage_codes) == len(level_three_challenges):
        log.success("Solved all level 3 challenges")
        return True
    else:
        log.critical("Failed to solve all level 3 challenges")
        return False


def solve_stage_four(stage_codes: dict, r) -> bool:
    level_four_solver = LevelFourSolver(ip, challenge_port, binary_dir, "./flag.txt", r)

    level_four_challenges = [f for f in os.listdir("binaries/level_4")]
    level_four_challenges.sort(key=lambda f: int(''.join(filter(str.isdigit, f))))

    for challenge in level_four_challenges:
        if not level_four_solver.solve_level(os.path.join(level_four_solver.binary_dir, challenge)):
            log.critical("Failed to solve level 4 challenge: {}".format(challenge))
            exit()

    for code in level_four_solver.stage_codes:
        stage_codes[(len(stage_codes))] = code

    if len(level_four_solver.stage_codes) == len(level_four_challenges):
        log.success("Solved all level 4 challenges")
        return True
    else:
        log.critical("Failed to solve all level 4 challenges")
        return False


def main():
    stage_codes = {}
    # There must be a better way to parse json keys as ints...
    if os.path.exists(stage_code_file):
        with open(stage_code_file, "rt") as f:
            temp_stage_codes = json.load(f)
        for code in temp_stage_codes.keys():
            stage_codes[int(code)] = temp_stage_codes[code]

    r = remote(ip, comms_port)
    r.sendline(b"reset")

    submit_already_solved(r, stage_codes)

    if not os.path.exists(os.path.join(binary_dir, "level_0")):
        collect_new_zip("level_0")

    if len(stage_codes) < len(os.listdir(os.path.join(binary_dir, "level_0"))):
        # solve level 0
        if not solve_stage_zero(stage_codes, r):
            exit(1)
        with open(stage_code_file, "wt") as f:
            json.dump(stage_codes, f, indent=4)

    else:
        log.info("Already solved level 0. Skipping")

    if not os.path.exists(os.path.join(binary_dir, "level_1")):
        collect_new_zip("level_1")

    if len(stage_codes) < len(os.listdir(os.path.join(binary_dir, "level_1"))) + \
            len(os.listdir(os.path.join(binary_dir, "level_0"))):
        # solve level 1
        if not solve_stage_one(stage_codes, r):
            exit(1)
        with open(stage_code_file, "wt") as f:
            json.dump(stage_codes, f, indent=4)
    else:
        log.info("Already solved level 1. Skipping")

    if not os.path.exists(os.path.join(binary_dir, "level_2")):
        collect_new_zip("level_2")

    if len(stage_codes) < len(os.listdir(os.path.join(binary_dir, "level_1"))) + \
            len(os.listdir(os.path.join(binary_dir, "level_0"))) +  \
            len(os.listdir(os.path.join(binary_dir, "level_2"))):
        # solve level 1
        if not solve_stage_two(stage_codes, r):
            exit(1)
        with open(stage_code_file, "wt") as f:
            json.dump(stage_codes, f, indent=4)
    else:
        log.info("Already solved level 2. Skipping")

    if not os.path.exists(os.path.join(binary_dir, "level_3")):
        collect_new_zip("level_3")

    if len(stage_codes) < len(os.listdir(os.path.join(binary_dir, "level_1"))) + \
            len(os.listdir(os.path.join(binary_dir, "level_0"))) +  \
            len(os.listdir(os.path.join(binary_dir, "level_2"))) + \
            len(os.listdir(os.path.join(binary_dir, "level_3"))):
        if not solve_stage_three(stage_codes, r):
            exit(1)
        with open(stage_code_file, "wt") as f:
            json.dump(stage_codes, f, indent=4)
    else:
        log.info("Already solved level 3. Skipping")

    if not os.path.exists(os.path.join(binary_dir, "level_4")):
        collect_new_zip("level_4")

    if len(stage_codes) < len(os.listdir(os.path.join(binary_dir, "level_1"))) + \
            len(os.listdir(os.path.join(binary_dir, "level_0"))) + \
            len(os.listdir(os.path.join(binary_dir, "level_2"))) + \
            len(os.listdir(os.path.join(binary_dir, "level_3"))) + \
            len(os.listdir(os.path.join(binary_dir, "level_4"))):
        if not solve_stage_four(stage_codes, r):
            pass
            # exit(1)
        with open(stage_code_file, "wt") as f:
            json.dump(stage_codes, f, indent=4)
    else:
        log.info("Already solved level 4. Skipping")

    collect_flags(stage_codes, r)


if __name__ == "__main__":
    main()
