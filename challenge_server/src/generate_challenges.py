import levels

if __name__ == "__main__":

    challenge_instances = {
        0: levels.ChallengeBuilder(0),
        1: levels.ChallengeBuilder(1),
        2: levels.ChallengeBuilder(2),
        3: levels.ChallengeBuilder(3),
        4: levels.ChallengeBuilder(4)
    }
    for i in range(len(challenge_instances)):
        print("Please wait...")
        challenge_builder = challenge_instances[i]
        challenge_builder.generate_challenges()
        challenge_builder.generate_zips()