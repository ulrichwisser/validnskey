# validnskey
Validnskey is a [Go](http://golang.org/) implementation to validate the DNSKEY RRset of a given zone against a set of given trust anchors.

## Status
This is a first working version.

## Installation
     go get github.com/ulrichwisser/validnskey

## Documentation
Example command line

    ./validnskey -z se -t se.trustanchor se.small
