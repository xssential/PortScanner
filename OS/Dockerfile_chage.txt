FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y p0f curl && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/log/p0f

WORKDIR /usr/local/bin

COPY run_p0f.sh /usr/local/bin/run_p0f.sh
RUN chmod +x /usr/local/bin/run_p0f.sh

ENTRYPOINT ["./run_p0f.sh"]