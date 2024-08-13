FROM alpine:latest

COPY ./main /usr/local/bin/rtop

#COPY ./private.key /root/.ssh/id_rsa
#COPY ./public.key /root/.ssh/id_rsa.pub
COPY id_ed25519 /root/.ssh/id_ed25519
COPY id_ed25519.pub /root/.ssh/id_ed25519.pub
RUN  chmod 600 /root/.ssh/*
COPY test.yaml /root/test.yaml
