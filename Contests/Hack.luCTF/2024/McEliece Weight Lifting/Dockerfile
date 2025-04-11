FROM sagemath/sagemath:latest
WORKDIR /home/sage
USER root
RUN apt-get update && apt-get install -y socat
USER sage
COPY . .
ENTRYPOINT ["/bin/sh"]
CMD ["-c", "socat tcp-listen:5555,fork,reuseaddr system:\"sage main.py\""]
