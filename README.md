# Magen Ingestion Service

[![Build Status](https://travis-ci.org/magengit/magen-in.svg?branch=master)](https://travis-ci.org/magengit/magen-in)
[![codecov](https://codecov.io/gh/magengit/magen-in/branch/master/graph/badge.svg)](https://codecov.io/gh/magengit/magen-in)
[![Code Health](https://landscape.io/github/magengit/magen-in/master/landscape.svg?style=flat)](https://landscape.io/github/magengit/magen-in/master)


Magen Ingestion Service is a microservice responsible for ingesting a digital data into the system. It exposes REST API
for managing digital assets. By assets we understand any sensitive resources that could be encrypted or wrapped
in order to restrict access to them.

Current version: ```1.3a16```

## Git clone

All of Magen services depend on an operations git submodule [**magen_helper**](https://github.com/magengit/magen-helper).
When cloning this repo, make sure to provide ```--recursive``` flag or after the clone execute a command to update ```magen-helpers``` git submodule:

```
git submodule update --init --recursive
```

For This Service there are available ```make``` commands. Makefile is located under [**ingestion/**](ingestion)

Make Default Target: ```make default```. Here is the list of targets available for ingestion

```make
default:
	@echo 'Makefile for Magen Ingestion Service'
	@echo
	@echo 'Usage:'
	@echo '	make clean    		:Remove packages from system and pyc files'
	@echo '	make test     		:Run the test suite'
	@echo '	make package  		:Create Python wheel package'
	@echo '	make install  		:Install Python wheel package'
	@echo '	make all      		:clean->package->install'
	@echo '	make list     		:List of All Magen Dependencies'
	@echo '	make build_docker 	:Pull Base Docker Image and Current Image'
	@echo '	make run_docker   	:Build and Run required Docker containers with mounted source'
	@echo '	make runpkg_docker	:Build and Run required Docker containers with created wheel'
	@echo '	make test_docker  	:Build, Start and Run tests inside main Docker container interactively'
	@echo '	make stop_docker  	:Stop and Remove All running Docker containers'
	@echo '	make clean_docker 	:Remove Docker unused images'
	@echo '	make rm_docker    	:Remove All Docker images if no containers running'
	@echo '	make doc		:Generate Sphinx API docs'
	@echo
	@echo
```

## Requirements: MacOS X
0. ```python3 -V```: Python **3.6.3** (>=**3.6.3**)
0. ```pip3 -V```: pip **9.0.1**
0. ```make -v```: GNU Make **3.81**
1. ```docker -v```: Docker version **17.03.0-ce**, build 60ccb22
2. ```docker-compose -v```: docker-compose version **1.11.2**, build dfed245
3. Make sure you have correct rights to clone Cisco-Magen github organization

## Requirements: AWS EC2 Ubuntu
0. ```python3 -V```: Python **3.6.3**
1. ```pip3 -V```: pip **9.0.1**
2. ```make -v```: GNU Make **4.1**
3. ```docker -v```: Docker version **17.03.0-ce**, build 60ccb22
4. ```docker-compose -v```: docker-compose version **1.11.2**, build dfed245
5. Make sure AWS user and **root** have correct rights to Cisco-Magen github organization

## Targets

1. ```make all```  -> Install *Magen-Core* dependencies, clean, package and install **ingestion** package
2. ```make test``` -> run **ingestion** tests

## Adopt this Infrastructure

1. get [**helper_scripts**](ingestion/helper_scripts) to the repo
2. follow the structure in [**docker_ingestion**](ingestion/docker_ingestion) to create ```docker-compose.yml``` and ```Dockerfile``` files
3. use [**Makefile**](ingestion/Makefile) as an example for building make automation

## Sphinx Documentation SetUp

There is a configured Sphinx API docs for the service.
To compile docs execute:

```make html``` in [```docs```](ingestion/docs) directory

or run:

```make doc``` in the [```ingestion```](ingestion) directory
