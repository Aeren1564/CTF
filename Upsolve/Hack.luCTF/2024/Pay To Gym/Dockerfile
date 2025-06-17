FROM python:alpine

RUN mkdir /app && adduser -D user && pip install pycryptodome sympy
WORKDIR /app
RUN apk add socat
COPY activator.py .
USER user
CMD [ "socat", "tcp-l:1234,reuseaddr,fork", "EXEC:'python activator.py'" ]
