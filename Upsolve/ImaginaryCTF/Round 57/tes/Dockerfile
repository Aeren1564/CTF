FROM ubuntu:22.04

RUN apt update -y
RUN apt install python3 python3-pip -y
RUN pip install flask playwright
RUN /usr/local/bin/playwright install-deps firefox
RUN /usr/local/bin/playwright install firefox

COPY . .

EXPOSE 8000
CMD ["python3", "server.py"]
