#!/bin/bash
docker rm -f pay-to-gym
docker build -t pay-to-gym .
docker run --name pay-to-gym -dp 127.0.0.1:1234:1234 pay-to-gym 
