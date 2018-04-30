# REST Connector

Enables interactions in your BonitaBPM processes with a REST API.

## Description

This connector provides the 4 main actions available in REST: _GET_,_POST_,_PUT_ and _DELETE_. 
It supports advanced security configuration like BASIC and DIGEST authentication mechanism, proxy and SSL configuration.

## Build

### Prerequisites

The parent of this project is not available in public repository so you must install it locally or in your corporate
repository manager.

So, install [bonita-connectors](https://github.com/bonitasoft/bonita-connectors) first.

### Build

__Clone__ or __fork__ this repository, then at the root of the project run:

`./mvnw clean verify`

## Release

Before releasing a new version make sure that the versionning of `.def` files are consistent with the implementation. In order to create a new release of the connector use the [_maven release plugin_](http://maven.apache.org/maven-release/maven-release-plugin/):

`./mvnw release:prepare`

It creates a new git _tag_ and update the current development version. New tags are automatically built on our CI infrastructure.
