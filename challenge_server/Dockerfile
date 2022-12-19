FROM ubuntu:20.04 as builder

ENV TOTAL_CHALLENGES=1000

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    build-essential \
    gcc \
    zip

WORKDIR /tmp
COPY src/requirements.txt ./
RUN pip3 install -r requirements.txt

COPY src/generate_challenges.py src/generate_stage_codes.py src/levels.py ./
COPY src/templates ./templates

RUN python3 generate_challenges.py && python3 generate_stage_codes.py


FROM python:3.10-slim

WORKDIR /challenge_server

COPY src/requirements.txt ./
RUN pip3 install -r requirements.txt && \
    useradd -m ctf -s /bin/bash -u 1000 -d /home/ctf

COPY src ./
COPY --from=builder /tmp/binaries ./binaries
COPY --from=builder /tmp/progress.txt ./
COPY --from=builder /tmp/zips ./zips

ENTRYPOINT ["python3", "/challenge_server/challenge_server.py"]