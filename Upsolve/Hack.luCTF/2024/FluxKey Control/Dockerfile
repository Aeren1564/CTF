FROM python:alpine

WORKDIR /challenge

RUN apk add --no-cache socat

COPY src/ .

ENTRYPOINT [ "socat", "tcp-l:1337,reuseaddr,fork", "exec:'python main.py'" ]
