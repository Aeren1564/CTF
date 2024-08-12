FROM python:3.12-slim

RUN pip3 install pycryptodome py_ecc gmpy2
RUN groupadd -r crypto && useradd -r -u 1001 -g crypto crypto

RUN mkdir -p /home/crypto
RUN chown -R crypto /home/crypto
USER crypto

COPY circuit.py ff_ct.py ff.py flag.py  gemini.py  server.py  impossible_xor.vk  instance.py  kzg.py  polynomial.py  proof_polynomials.py  prover.py  relations.py  ronk_srs.bin  server.py shplonk.py srs_gen.py standard_xor.vk sumcheck.py transcript.py uint.py /home/crypto/

WORKDIR /home/crypto

EXPOSE 1337

CMD ["python3","/home/crypto/server.py"]