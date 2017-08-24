#! /usr/bin/env bash

docker pull mongo

ingestion/helper_scripts/aws_login.sh

docker pull 079349112641.dkr.ecr.us-west-2.amazonaws.com/magen-ingestion:latest

docker run -d --name="magen_mongo" mongo
# once new magen_ingestion is uploaded to AWS change image below to
# 079349112641.dkr.ecr.us-west-2.amazonaws.com/magen-ingestion
# -it mode can be changed to -d when running actual test
docker run -it -p 5020:5020 --link="magen_mongo" magen_ingestion:v1.0

