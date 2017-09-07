MAGEN_HELPER=../../lib/magen_helper
staging_dir=$(shell pwd)

mkcmn_docker_compose_service_name=magen_ingestion
mkcmn_docker_compose_service_port=5020

include $(MAGEN_HELPER)/make_common/docker_compose_common.mk

docker_compose_build: common_docker_compose_build

docker_compose_rundev: common_docker_compose_rundev

docker_compose_runpkg: common_docker_compose_runpkg

docker_compose_test: common_docker_compose_test
