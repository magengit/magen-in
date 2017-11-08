FROM magendocker/magen-core:latest
MAINTAINER Alena Lifar

VOLUME ["/opt/server"]
WORKDIR /opt/server
ENV PYTHONPATH $PYTHONPATH:/opt/server:/opt/server/ingestion:/opt/server/ingestion/ingestion_server

RUN rm -rf __pycache__/
RUN rm -rf tests/__pycache__/

WORKDIR /opt/server/ingestion

RUN rm -rf __pycache__/
RUN rm -rf tests/__pycache__/

# For production:
# RUN pip3 install magen-ingestion-service

# For dev:
WORKDIR /tmp
COPY magen*.whl /tmp
RUN pip3 install magen*.whl

WORKDIR /opt/server/ingestion
