FROM python:3.11-alpine

WORKDIR /hexhttp/
ADD . /hexhttp/

RUN pip install -r requirements.txt
RUN chmod +x hexhttp.py

ENTRYPOINT ["/hexhttp/hexhttp.py"]