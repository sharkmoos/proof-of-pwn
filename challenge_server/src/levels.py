"""
TODO: Add cruff functions to all of the programs. Ideally with lots of random strings
TODO: Add cruff strings to the main function. So people dont get any clever ideas of only parsing the strings inside mains vmspace
"""

import concurrent.futures
import jinja2
import random
import string
import subprocess
import logging
import os


logging.basicConfig(level=logging.DEBUG)
environment: jinja2.environment.Environment = jinja2.Environment(loader=jinja2.FileSystemLoader("."))
code_dir: str = "binary_source/"    # where the output of the templates go
ex_dir: str = "/tmp/binaries/"  # the actual challenge executables
zip_dir: str = "/tmp/zips/"  # the zips that the player downloads
compilation_options: list = ["gcc", "-O0", "-fno-stack-protector", "-no-pie"]   # currently all the binaries are compiled the same
challenge_count = 0

# all the challenge configs
challenge_maps: dict = {
    0: {
        # single ret2win
        "name": "level0",
        "source_path": os.path.join(code_dir, "level0"),
        "binary_path": os.path.join(ex_dir, "level0"),
        "zip_path": os.path.join(ex_dir, "level0.zip"),
        "binary_count": 1,
    },
    1: {
        # 5 ret2wins
        "name": "level1",
        "source_path": os.path.join(code_dir, "level1"),
        "binary_path": os.path.join(ex_dir, "level1"),
        "zip_path": os.path.join(ex_dir, "level1.zip"),
        "binary_count": 5,
    },
    2: {
        # 50 ret2libc
        "name": "level2",
        "source_path": os.path.join(code_dir, "level2"),
        "binary_path": os.path.join(ex_dir, "level2"),
        "zip_path": os.path.join(ex_dir, "level2.zip"),
        "binary_count": 5,
    },
    3: {
        # 100 ret2libc + stack cookie
        "name": "level3",
        "source_path": os.path.join(code_dir, "level3"),
        "binary_path": os.path.join(ex_dir, "level3"),
        "zip_path": os.path.join(ex_dir, "level3.zip"),
        "binary_count": 5,
    },
    4: {
        # 100 ret2libc + stack cookie
        "name": "level4",
        "source_path": os.path.join(code_dir, "level4"),
        "binary_path": os.path.join(ex_dir, "level4"),
        "zip_path": os.path.join(ex_dir, "level4.zip"),
        "binary_count": 5,
    }
}


class ChallengeBuilder:
    """
    This class is the template for all challenge generation
    """
    def __init__(self, challenge_id: int) -> None:
        """
        Initialize the challenge builder. Most of the configs are created based on the challenge_id param
        :param challenge_id: The challenge id, basically the key of the challenge_maps dict
        """
        self.level: int = challenge_id
        self.name: str = challenge_maps[challenge_id]["name"]
        self.source_path: str = challenge_maps[challenge_id]["source_path"]
        self.binary_path: str = challenge_maps[challenge_id]["binary_path"]
        self.binary_count: int = challenge_maps[challenge_id]["binary_count"]
        self.zip_path: str = os.path.join(zip_dir, self.name, self.name) + ".zip"

        self.template_file = environment.get_template(f"templates/{self.name}/template.c")

    def randomword(self, length: int) -> str:
        """
        Create the stack cookie value
        :param length: Generate a random string of length length.
        :return:
        """
        letters: str = string.ascii_lowercase
        return ''.join(random.choice(letters) for i in range(length))

    def generate_cruff_function(self) -> str:
        """
        Generate a random C function
        :return:
        """
        cruff_function: str = ""
        cruff_function += "void " + self.randomword(random.randint(5, 10)) + "(){\n"
        for line in range(random.randint(5, 15)):
            cruff_function += f"char {self.randomword(random.randint(5, 10))}[] = \"{self.randomword(random.randint(5, 10))}\";\n"
        cruff_function += "}\n\n"

        return cruff_function

    def generate_cruff_functions(self, amount) -> str:
        """
        Generate random C functions filled with random strings
        :param amount:
        :return:
        """
        cruff_functions: str = ""
        for i in range(amount):
            cruff_functions += self.generate_cruff_function()
        return cruff_functions

    def generate_c(self, file_name: str, random_string: str = "") -> None:
        """
        Generate C code file from the template
        :param file_name:
        :param random_string:
        :return:
        """
        global challenge_count
        with open(os.path.join(self.source_path, file_name), "w") as result:
            if self.name != "level4":
                buf_size = random.randint(50, 200)
            else:
                # Needs to be smaller than most challs, not expecting people to refactor angr
                buf_size = random.randint(16, 48)

            # generate from C file from template
            result.write(self.template_file.render(
                {
                    "random_string": random_string,
                    "challenge_name": f"Challenge: {challenge_count}",
                    "random_string_len": len(random_string),
                    "buf_size": buf_size,
                    "cruff_functions": self.generate_cruff_functions(random.randint(5, 15)),
                    "random_seed": random.randint(1, 50),
                }
            ))
        challenge_count += 1

    def generate_challenges(self) -> None:
        """
        Prepare and compile the challenges from template form to compilation
        :return:
        """
        if not os.path.isdir(self.source_path):
            if not os.path.isdir(code_dir):
                os.mkdir(code_dir)
            os.mkdir(self.source_path)
        if not os.path.isdir(ex_dir):
            os.mkdir(ex_dir)

        file_names: list = [f"binary_{i}" for i in range(self.binary_count)]
        logging.debug(f"Generating C file with names: {file_names}")
        for i in file_names:
            if self.level > 2:
                string_length: int = random.randint(5, 20)
                rand_string: str = self.randomword(string_length)
                self.generate_c(self.name + "_" + i + ".c", rand_string)
            else:
                self.generate_c(self.name + "_" + i + ".c")

        # I'm guessing it's at least partially a subprocess startup overhead for gcc
        # so threads will actually help here
        # TODO: See whether ProcessPoolExecutor is faster in this situation
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            counter = 0
            if not os.path.isdir(self.binary_path):
                os.mkdir(self.binary_path)
            for challenge in sorted(os.listdir(self.source_path)):
                compile_command: list = compilation_options[:]  # pass by value not reference
                compile_command.append(os.path.join(self.source_path, challenge))
                compile_command.append("-o")
                compile_command.append(os.path.join(ex_dir, self.binary_path, f"level_{counter}"))
                logging.info("is: {compile_command}")
                logging.debug(f"Running command in a subprocess: {compile_command}")
                pool.submit(subprocess.run, compile_command, capture_output=True)
                counter += 1

    def generate_zips(self):
        """
        Generate the zip files for the challenge stages
        :return:
        """
        if not os.path.isdir(zip_dir):
            os.mkdir(zip_dir)
        if not os.path.isdir(os.path.join(zip_dir, self.name)):
            os.mkdir(os.path.join(zip_dir, self.name))

        challenges = sorted(self.binary_path + "/" + i for i in os.listdir(self.binary_path))
        command = f"zip -j {self.zip_path} {' '.join(challenges)}"
        logging.debug(f"Zipping with command: {command}")
        output = os.popen(command).read()
        logging.debug(output)
