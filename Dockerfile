FROM python:3.11.6-alpine

WORKDIR /root/
ADD . /root/

RUN apk add \
    gcc \
    musl-dev \
    libffi-dev \
    openssl-dev \
    libffi-dev

RUN pip install -r requirements.txt
RUN chmod +x hexhttp.py

ENTRYPOINT ["./hexhttp.py"]
CMD ["--help"]