FROM python:slim AS app
RUN pip install --no-cache-dir pycryptodome
FROM pwn.red/jail
COPY --from=app / /srv
COPY sums.py /srv/app/run
RUN chmod +x /srv/app/run
# verifier from https://github.com/tsunrise/sumcheck_multilinear/ 
COPY IPProverLinear.py /srv/app/
COPY IPVerifier.py /srv/app/
COPY polynomial.py /srv/app/
COPY flag.txt /srv/app/
ENV JAIL_TMP_SIZE=65536 JAIL_MEM=20M JAIL_PIDS=10 JAIL_TIME=300