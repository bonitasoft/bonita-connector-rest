#REST Connector

Enables interactions in your BonitaBPM processes with a REST API.

##Description

This connector provides the 4 main actions available in REST: _GET_,_POST_,_PUT_ and _DELETE_. 
It supports advanced security configuration like BASIC and DIGEST authentication mechanism, proxy and SSL configuration.

##Build

__Clone__ or __fork__ this repository, then at the root of the project run:

`mvn clean verify`

##Release

Before releasing a new version make sure that the versionning of `.def` files are consistent with the implementation. In order to create a new release of the connector use the _maven release plugin_:

`mvn release:prepare`

It creates a new git _tag_ and update the current development version. New tags are automatically built on our CI infrastructure.
