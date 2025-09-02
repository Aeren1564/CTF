FROM python:3.13.6

RUN apt update && DEBIAN_FRONTEND=noninteractive apt install -y zip unzip

RUN mkdir /drive
WORKDIR /drive

EXPOSE 5487

ENV PYTHONDONTWRITEBYTECODE=x

CMD ["python", "-B", "/drive/server.py"]
