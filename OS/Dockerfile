FROM debian:latest

RUN apt update && apt install -y \
    p0f \
    curl \
    dos2unix \
    && apt clean

COPY run_p0f.sh /usr/local/bin/run_p0f.sh

RUN dos2unix /usr/local/bin/run_p0f.sh

RUN chmod +x /usr/local/bin/run_p0f.sh

WORKDIR /usr/local/bin

ENTRYPOINT ["./run_p0f.sh"]