FROM python:3.13-slim

RUN apt-get update && apt-get -y upgrade
RUN apt-get install -y gcc
RUN apt-get install -y libsqlite3-0
RUN apt-get install -y libsqlite3-dev
RUN apt-get install sqlite3 sqlite3-doc

COPY requirements.txt /
RUN pip install --no-cache-dir -r /requirements.txt

COPY server.py /srv/
COPY secret.py /srv/

EXPOSE 8000

CMD ["python3", "/srv/server.py"]
