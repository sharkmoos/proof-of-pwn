FROM python:3.10-slim

ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /challenge_handler

COPY src/ .


ENTRYPOINT ["python3", "/challenge_handler/challenge_handler.py"]
