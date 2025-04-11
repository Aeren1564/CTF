FROM ubuntu@sha256:aa772c98400ef833586d1d517d3e8de670f7e712bf581ce6053165081773259d

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -yq python3 python3-pip openssl && rm -rf /var/lib/apt/lists/*

# This next line creates a key, only for local testing
RUN openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes -subj "/C=US/ST=PA/L=Ashwood Hollow/CN=tales-from-the-crypt.chal.pwni.ng"

COPY ./requirements.txt /
RUN pip3 install -r requirements.txt

COPY ./server.py /
COPY ./util.py /

EXPOSE 1337

CMD ["python3", "server.py"]
