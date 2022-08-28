import concurrent.futures
import jinja2
import random
import string
import argparse
import os
import subprocess
import logging

logging.basicConfig(level=logging.DEBUG)
environment = jinja2.Environment(loader=jinja2.FileSystemLoader("."))
template_file = environment.get_template("template.c")
code_dir: str = "binary_source/"
binary_dir: str = "binaries/"
compilation_options: list = ["gcc", "-O0"]


def randomword(length: int):
    """
    :param length: Generate a string of this length
    :return: return the string of length 'length'
    """
    letters: str = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))


def generate_c(size: int, random_increase: int, random_string: str, file_name: str):
    """
    :param size: Size of user input buffer
    :param random_increase: random value to add to buffer length when finding string length
    :param random_string: String to be compared at start of buffer
    :param file_name: to be used when naming file
    :return:
    """
    with open(file_name, "w") as result:
        result.write(template_file.render(
            {
                "size": size,
                "random_increase": random_increase,
                "random_string": random_string,
                "random_string_len": len(random_string),
                "challenge_name": file_name.split("/")[1][:-2]
            }
        ))


def generate_challenges(number_of_outputs: int):
    if not os.path.isdir(code_dir):
        os.mkdir(code_dir)
    if not os.path.isdir(binary_dir):
        os.mkdir(binary_dir)

    file_names: list = [f"binary_{i}" for i in range(number_of_outputs)]
    logging.debug(f"Generating C file with names: {file_names}")
    for i in file_names:
        size: int = random.randint(21, 200)
        increase: int = random.randint(0, 500)
        string_length: int = random.randint(5, 20)
        rand_string: str = randomword(string_length)
        generate_c(size, increase, rand_string, code_dir + i+".c")

    for file in file_names:
        compile_command: list = compilation_options[:] # pass by value not reference
        compile_command.append(code_dir + file + ".c")
        compile_command.append("-o")
        compile_command.append(binary_dir + file)
        logging.debug(f"Running command in a subprocess: {compile_command}")
        subprocess.run(compile_command, capture_output=True)
    return


def serve_challenges():
    print("Reversing Automation Test Machine v1.0\n\n")
    binaries: list = [binary_dir + name for name in os.listdir(binary_dir) if os.path.isfile(binary_dir + name)]
    random.shuffle(binaries)
    process = subprocess.Popen([binaries[0]])
    process.communicate()
    if process.returncode != 1:

    print(f"\nGot return code: {process.returncode}")

    return


def main(serve=False, generate=0):
    if generate != 0:
        generate_challenges(generate)
    if serve:
        serve_challenges()
    return


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Manage Automation Challenge')
    parser.add_argument('--generate', default=0, type=int, help='Generate the challenge binaries')
    parser.add_argument('--serve', action="store_true",  default=False, help="Serve the challenge")
    args = parser.parse_args()

    main(args.serve, args.generate)
