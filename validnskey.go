package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/miekg/dns"
	"github.com/ulrichwisser/godnssecvalid"
)

func main() {

	// define and parse command line arguments
	var verbose bool = false
	var trustanchorfile string = ""
	var zone string = ""

	flag.BoolVar(&verbose, "v", false, "print more information while running")
	flag.StringVar(&zone, "zone", "", "zone name")
	flag.StringVar(&zone, "z", "", "zone name")
	flag.StringVar(&trustanchorfile, "trust", "", "file containing DS records for trust anchors")
	flag.StringVar(&trustanchorfile, "t", "", "file containing DS records for trust anchors")
	flag.Parse()

	if flag.NArg() != 1 || trustanchorfile == "" || zone == "" {
		fmt.Printf("Usage: %s [-v] -z <zone> -t <trustanchorfile> zonefile \n", os.Args[0])
		flag.Usage()
		os.Exit(1)
	}

	zone = dns.Fqdn(zone)

	trustf, err := os.Open(trustanchorfile)
	if err != nil {
		panic(err)
	}

	//
	var trust []dns.RR = make([]dns.RR, 0)
	for token := range dns.ParseZone(trustf, "", "") {
		if token.Error != nil {
			fmt.Println("Error: ", token.Error)
		}
		if token.RR.Header().Rrtype == dns.TypeDS && token.RR.Header().Name == zone {
			trust = append(trust, token.RR)

		}
	}
	trustf.Close()

	//
	if verbose {
		fmt.Println("Trustanchor(s)")
		for _, rr := range trust {
			fmt.Println(rr.String())
		}
		fmt.Println()
	}

	//
	// ZONE FILE
	//
	zonef, err := os.Open(flag.Arg(0))
	if err != nil {
		panic(err)
	}

	//
	var dnskey []dns.RR = make([]dns.RR, 0)
	var rrsig []dns.RR = make([]dns.RR, 0)
	for token := range dns.ParseZone(zonef, "", "") {
		if token.Error != nil {
			fmt.Println("Error: ", token.Error)
		}
		if token.RR.Header().Name != zone {
			continue
		}
		if token.RR.Header().Rrtype == dns.TypeDNSKEY {
			dnskey = append(dnskey, token.RR)
		}
		if token.RR.Header().Rrtype == dns.TypeRRSIG && token.RR.(*dns.RRSIG).TypeCovered == dns.TypeDNSKEY {
			rrsig = append(rrsig, token.RR)
		}
	}
	zonef.Close()

	for _, rr := range rrsig {
		dnskey = append(dnskey, rr)
	}

	//
	if verbose {
		fmt.Println("Chain")
		for _, rr := range dnskey {
			fmt.Println(rr.String())
		}
		fmt.Println()
	}

	// print result
	valid := godnssecvalid.ValidateChain(dnskey, trust)
	if valid {
		fmt.Println("DNSKEY RRset is valid")
	} else {
		fmt.Println("DNSKEY RRset is not valid")
	}
}
