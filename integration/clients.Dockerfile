FROM python:3.13-alpine

RUN apk add --no-cache lftp openssh-client putty sshpass && pip install --no-cache-dir paramiko scp boto3