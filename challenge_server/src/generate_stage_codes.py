import os
import pickle
import uuid


def generate_stage_codes(number_of_codes) -> list:
    the_stage_codes = []
    while len(the_stage_codes) != number_of_codes:
        code = uuid.uuid4().hex
        if code not in the_stage_codes:
            the_stage_codes.append(code)

    return the_stage_codes


if __name__ == "__main__":
    stage_codes = generate_stage_codes(int(os.getenv("TOTAL_CHALLENGES")))
    with open("/tmp/progress.txt", "wb") as f:
        pickle.dump(stage_codes, f)