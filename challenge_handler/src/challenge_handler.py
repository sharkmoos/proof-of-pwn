#!/usr/bin/env python3
"""
TODO:
"""

import logging
import os
import pickle
import socketserver
import multiprocessing
import http.server
import time


log = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

TOTAL_CHALLENGES = 21  # int(os.getenv("TOTAL_CHALLENGES"))  # TODO: Initiate this properly once you're testing all challs
challenge_progress = 0  # total number of challenges completed
current_level_stage = 0  # overall stages ( 1 - 4 )
max_challenges = 0  # displayed number of challenges overall. Increases each time a stage is complete
flag_count = 0  # TODO: This does more than it probably should, and is semi redundant due to the current_level_stage var. Will remove if I have time
http_thread_ptr: multiprocessing.Process = None  # This is a bit of a mess. Still, multi processing is a mess
http_port = 4750

socketserver.TCPServer.allow_reuse_address = True

# The keys represent the value of challenge_progress to trigger a flag.
flags = {
    1: "cueh{n00b_p0w3rrr}",
    6: "cueh{n0t_s0_n00b_n0w}",
    11: "cueh{50}",
    16: "cueh{750}",
    21: "cueh{1000}"
}

# level names are the same as the zip file directories
levels = ["level0", "level1", "level2", "level3", "level4"]


class BinaryDownloadHandler(http.server.BaseHTTPRequestHandler):
    """
    Manage the HTTP server to provision the challenge binaries.
    """

    def __init__(self, request: bytes, client_address: tuple[str, int], server: socketserver.BaseServer):
        super().__init__(request, client_address, server)
        self.level_zip = ""

    def do_GET(self):
        """
        Provide the appropriate zip file for the current level.
        :return:
        """
        with open(self.level_zip, 'rb') as file:
            self.send_response(200)
            self.send_header('Content-type', 'application/zip')
            self.send_header(f'Content-Disposition', f'attachment; filename="level_{flag_count}"')
            self.end_headers()
            self.wfile.write(file.read())


def serve_level(level, port):
    """
    Serve the level zip file using the BinaryDownloadHandler.
    :param level: The directory and name of the level zip file.
    :param port: The port to serve the zip file on.
    :return:
    """
    handler = BinaryDownloadHandler
    handler.level_zip = f"/challenge_server/zips/{level}/{level}.zip"
    while True:  # sometimes the socket is still occupied, usually attempting frees it up though
        try:
            with socketserver.TCPServer(("0.0.0.0", port), handler) as httpd:
                logging.info(f"Http Server Serving level '{level}' on port {port}")
                httpd.serve_forever()
                break
        except OSError:
            logging.warning("Port already in use. Retrying in 1 seconds")
            time.sleep(1)


def start_http_server(level: str):
    """
    Serve the challenge ZIP in a new process.
    :param level: The level to serve.
    :return:
    """
    global http_thread_ptr
    http_thread_ptr = multiprocessing.Process(target=serve_level, args=(level, http_port,))
    http_thread_ptr.start()


def stop_http_server():
    """
    Stop the HTTP server.
    """
    global http_thread_ptr
    http_thread_ptr.terminate()
    http_thread_ptr.join()  # wait for the process to finish
    # requests.get(f"http://localhost:{http_port}/")  # this is a hack to get the server port to free


class ChallengeRequestHandler(socketserver.BaseRequestHandler):
    def __init__(self, request, client_address, server):
        super().__init__(request, client_address, server)
        self.position = None
        self.next_stage_code: str = ""

    def print_banner(self):
        """
        Print the banner. Just some ASCII art tbh.
        :return:
        """
        self.request.send(b"\033c")
        self.request.send(f"{'':#<30}\n".encode())
        self.request.send(f"{'  Heart of Pwn    ':#^30}\n".encode())
        self.request.send(f"{'':#<30}\n".encode())
        current_solves = f"Progress: {challenge_progress}/{max_challenges}"
        self.request.send(f"\n\n{current_solves}\n".encode())

    def win(self):
        """
        Print the win flag.
        :return:
        """
        self.print_banner()
        self.request.send(b"Congratulations! You've completed the CTF!\n")
        self.request.send(f"Here's the final flag: {list(flags.values())[-1]}\n".encode())
        self.request.send(b"Thanks for playing!\n")

    def handle(self):
        """
        Handle the challenge request. Most of the challenge logic resides here. It's a little messy
        because my brain doesn't cope well with event based programming.
        :return:
        """
        # TODO: Make the globals less global
        global http_thread_ptr, current_level_stage, max_challenges, flag_count, challenge_progress

        # if the player has completed all challenges, don't bother with the rest of the logic
        if flag_count == len(flags):
            self.win()
            return

        try:
            self.next_stage_code = stage_codes[challenge_progress + 1]

            self.print_banner()
            self.request.send(b"\n\n- Hit enter to start from the beginning\n")
            self.request.send(b"- Enter a stage code to resume progress.\n")
            self.request.send(b"- Make sure you've read the CTFd instructions before you start!\n")

            # Tricky one, I feel like we should stop once the player has completed all the challenges
            # but it's a pain for testing.
            # while challenge_progress < TOTAL_CHALLENGES:
            while True:
                self.request.send(b"Stage Code: ")
                try:
                    stage_code = self.request.recv(1024).decode().strip()
                except UnicodeDecodeError:
                    self.request.send(b"Invalid input\n")
                    continue

                # these 5 variables basically control the challenge state, so need to
                # reset them all
                if stage_code == "reset":
                    challenge_progress = 0
                    current_level_stage = 0
                    flag_count = 0
                    max_challenges = list(flags.keys())[0]

                elif stage_code == self.next_stage_code:
                    challenge_progress += 1
                    self.next_stage_code = stage_codes[challenge_progress + 1]

                elif stage_code in stage_codes:
                    self.request.send(b"Valid stage code, wrong stage\n")

                else:
                    self.request.send(b"Unrecognised stage code.\n")
                    continue

                # write to the FIFO to tell the challenge_server to prepare the next binary.
                with open("/challenge_server/current_level", "wt") as fifo:
                    log.debug(f"Sending signal to start level {challenge_progress} with stage code {self.next_stage_code}")
                    fifo.write(f"{challenge_progress},{self.next_stage_code}")

                # at the end of each stage, we need to provide a flag and release the next ZIP
                if challenge_progress in flags:
                    flag_count += 1
                    if flag_count == len(flags):
                        self.win()
                        return

                    current_level_stage += 1
                    stop_http_server()
                    start_http_server(levels[current_level_stage])
                    max_challenges = list(flags.keys())[flag_count]
                    self.print_banner()
                    self.request.send(f"\nWell done! You earned a flag: {flags[challenge_progress]}\n".encode())
                    self.request.send(f"Head back over to port {http_port} to get the next challenge zip! \n\n".encode())

                else:
                    self.next_stage_code = stage_codes[challenge_progress + 1]
                    self.print_banner()
                self.request.send(f"Loading level {challenge_progress}\n".encode())
        except BrokenPipeError:
            log.info("Client ended connection")


def main():
    start_http_server(levels[current_level_stage])
    with socketserver.TCPServer(("0.0.0.0", 1337), ChallengeRequestHandler) as s:
        s.serve_forever()


if __name__ == "__main__":
    time.sleep(2)
    max_challenges = list(flags.keys())[0]
    current_level_stage = 0

    log.debug("Getting stage codes")
    with open("/challenge_server/progress.txt", "rb") as f:
        stage_codes = pickle.load(f)
    with open("/challenge_server/current_level", "wt") as f:
        f.write(f"{challenge_progress},{stage_codes[challenge_progress + 1]}")
    main()
