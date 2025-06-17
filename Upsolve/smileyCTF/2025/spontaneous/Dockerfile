FROM python:slim AS app
FROM pwn.red/jail
COPY --from=app / /srv
COPY server.py /srv/app/run
RUN chmod +x /srv/app/run
COPY flag.txt /srv/app/
COPY compression.py /srv/app/
COPY fft.py /srv/app/
COPY merkletree.py /srv/app/
COPY params.py /srv/app/
COPY transcript.py /srv/app/
COPY Verifier.py /srv/app/
COPY ZKP.py /srv/app/
ENV JAIL_TMP_SIZE=65536 JAIL_MEM=20M JAIL_PIDS=10 JAIL_TIME=300