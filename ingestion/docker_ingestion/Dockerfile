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
COPY magen_ingestion_service-1.1a2-py3-none-any.whl /tmp
RUN pip3 install magen_ingestion_service-1.1a2-py3-none-any.whl

WORKDIR /opt/server/ingestion
