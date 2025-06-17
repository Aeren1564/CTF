# You don't need to read this file in order to solve the challenge
FROM python:3.12.7-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -yqq socat hashcash
RUN pip install pycryptodome
ADD server.py server.py
ADD run.sh run.sh

CMD socat TCP-L:9999,fork,reuseaddr EXEC:"./run.sh"
