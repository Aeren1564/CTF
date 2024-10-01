FROM python:3-slim

RUN apt-get update && \
apt-get install -y socat && \
pip3 install --no-cache-dir pillow

WORKDIR /opt/app
COPY main.py tree_store.py make_flag.py ter-x32b.pbm ter-x32b.pil ./
RUN python make_flag.py && rm make_flag.py
CMD socat -d -d -s TCP-LISTEN:1024,reuseaddr,fork EXEC:'timeout 300 python -u /opt/app/main.py',stderr
