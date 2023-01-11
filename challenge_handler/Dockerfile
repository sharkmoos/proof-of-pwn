FROM python:3.10-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV TOTAL_CHALLENGES=1000
WORKDIR /challenge_handler

COPY src/requirements.txt /tmp
RUN pip3 install -r /tmp/requirements.txt
COPY src/ .


ENTRYPOINT ["python3", "/challenge_handler/challenge_handler.py"]
