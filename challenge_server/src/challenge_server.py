"""
TODO:
"""

import logging
import os
import subprocess

import levels

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

# Each of the challenge stages is a distinct class object
challenge_instances = {
    0: levels.ChallengeBuilder(0),
    1: levels.ChallengeBuilder(1),
    2: levels.ChallengeBuilder(2),
    3: levels.ChallengeBuilder(3),
    4: levels.ChallengeBuilder(4),
}


def load_challenge(challenge_name, stage_code):
    """
    Load the challenge binary into the jail on the xinetd container
    :param challenge_name: The name of the challenge binary to copy over
    :param stage_code: The stage code to be put in the jail for the player to obtain
    :return:
    """
    logging.debug("Running challenge: " + challenge_name)
    copy1 = subprocess.Popen(["cp", challenge_name, "/jail/challenge"])
    copy1.wait()
    while copy1.poll() != 0:
        log.warning("Error copying challenge to jail")
        copy1 = subprocess.Popen(["cp", challenge_name, "/jail/challenge"])
        copy1.wait()

    with open("/jail/stage_code", "wt") as f:
        f.write(stage_code)


def main():
    current_level = 0
    # read from the fifo to get the level and stage_code
    while True:
    #while current_level < TOTAL_CHALLENGES - 1:
        with open("/challenge_server/current_level", "rb") as f:
            current_level, stage_code = f.read().decode().split(",")
            current_level = int(current_level)

        # have to continue to read from the fifo even if we have solved all the levels
        # otherwise it will block and freeze challenge handler container
        load_challenge(challenge_binaries[current_level], stage_code)


if __name__ == "__main__":
    if not os.path.isfile("./current_level"):
        os.mkfifo("./current_level")

    challenge_binaries = {}
    counter = 0
    for challenge_stage in sorted(os.listdir("/challenge_server/binaries/")):
        challenges = [f for f in os.listdir(os.path.join("/challenge_server/binaries/", challenge_stage))]
        challenges.sort(key=lambda f: int(''.join(filter(str.isdigit, f))))
        for challenge in challenges:
            challenge_binaries[counter] = os.path.join("/challenge_server/binaries/", challenge_stage, challenge)
            counter += 1

    main()

