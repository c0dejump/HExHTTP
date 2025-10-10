FROM python:3.11-alpine

WORKDIR /hexhttp/
ADD . /hexhttp/

RUN apk update && apk upgrade 
RUN pip install .
RUN chmod +x hexhttp.py

ENTRYPOINT ["/hexhttp/hexhttp.py"]