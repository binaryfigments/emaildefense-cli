package cmd

import (
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

type mxrecords struct {
	AuthenticatedData bool      `json:"authenticated_data"`
	MX                []*dns.MX `json:"mx,omitempty"`
}

func getMX(domain string, nameserver string) (*mxrecords, error) {
	data := new(mxrecords)

	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeMX)
	m.RecursionDesired = true
	m.SetEdns0(4096, true)

	r, _, err := c.Exchange(m, net.JoinHostPort(nameserver, "53"))
	if r == nil {
		return data, err
	}

	if r.Rcode != dns.RcodeSuccess {
		err = errors.New("mx record lookup not successful")
		return data, err
	}

	data.AuthenticatedData = r.AuthenticatedData

	for _, r := range r.Answer {
		if a, ok := r.(*dns.MX); ok {
			data.MX = append(data.MX, a)
		}
	}

	return data, err
}

type spfrecords struct {
	Record            string   `json:"domain,omitempty"`
	SPF               []string `json:"spf,omitempty"`
	AuthenticatedData bool     `json:"authenticated_data"`
}

// Get function of this package.
func getSPF(domain string, nameserver string) (*spfrecords, error) {
	data := new(spfrecords)
	data.Record = domain

	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(data.Record), dns.TypeTXT)
	m.RecursionDesired = true
	m.SetEdns0(4096, true)

	r, _, err := c.Exchange(m, net.JoinHostPort(nameserver, "53"))
	if r == nil {
		return data, err
	}

	if r.Rcode != dns.RcodeSuccess {
		err = errors.New("spf record lookup not successful")
		return data, err
	}

	switch rcode := r.MsgHdr.Rcode; rcode {
	case dns.RcodeSuccess:
		for _, r := range r.Answer {
			if a, ok := r.(*dns.TXT); ok {
				// SPF records zijn langer en kunnen dus in meerdere delen teruggegeven worden.
				// strings.Join plakt ze weer aan elkaar.
				record := strings.Join(a.Txt, "")
				record = strings.ToLower(record)
				if strings.Contains(record, "v=spf1") {
					data.SPF = append(data.SPF, record)
				}
			}
		}
	default:
		err = errors.New("dns error code for spf lookup : " + strconv.Itoa(r.MsgHdr.Rcode))
		return data, err
	}

	data.AuthenticatedData = r.AuthenticatedData

	return data, nil
}

type dmarcrecords struct {
	Record            string   `json:"domain,omitempty"`
	DMARC             []string `json:"dmarc,omitempty"`
	AuthenticatedData bool     `json:"authenticated_data"`
}

// Get function of this package.
func getDMARC(domain string, nameserver string) (*dmarcrecords, error) {
	data := new(dmarcrecords)
	data.Record = "_dmarc." + domain

	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(data.Record), dns.TypeTXT)
	m.RecursionDesired = true
	m.SetEdns0(4096, true)

	r, _, err := c.Exchange(m, net.JoinHostPort(nameserver, "53"))
	if r == nil {
		return data, err
	}

	if r.Rcode != dns.RcodeSuccess {
		err = errors.New("dns error code for dmarc lookup : " + strconv.Itoa(r.MsgHdr.Rcode))
		return data, err
	}

	for _, r := range r.Answer {
		if a, ok := r.(*dns.TXT); ok {
			// dmarc records zijn soms langer en kunnen dus in meerdere delen teruggegeven worden.
			// strings.Join plakt ze weer aan elkaar.
			record := strings.Join(a.Txt, "")
			record = strings.ToLower(record)
			if strings.Contains(record, "v=dmarc1") {
				data.DMARC = append(data.DMARC, record)
			}
		}
	}

	data.AuthenticatedData = r.AuthenticatedData

	return data, nil
}

type dkimrecords struct {
	Record            string `json:"domain,omitempty"`
	DomainKey         string `json:"domainkey,omitempty"`
	AuthenticatedData bool   `json:"authenticated_data"`
}

// Do lookup _domainkey.example.org
// if exists -----> DNS response: NOERROR
// if not exists -> DNS response: NXDOMAIN

func getDKIM(domain string, nameserver string) (*dkimrecords, error) {
	data := new(dkimrecords)
	data.Record = "_domainkey." + domain

	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(data.Record), dns.TypeTXT)
	m.RecursionDesired = true
	m.SetEdns0(4096, true)

	r, _, err := c.Exchange(m, net.JoinHostPort(nameserver, "53"))
	if r == nil {
		return data, err
	}

	// Meer uitlag later
	switch rcode := r.MsgHdr.Rcode; rcode {
	case dns.RcodeSuccess:
		data.DomainKey = "Success" // NoError (0)
	case dns.RcodeFormatError:
		data.DomainKey = "FormErr" // FormErr (1)
	case dns.RcodeServerFailure:
		data.DomainKey = "ServFail" // ServFail (2)
	case dns.RcodeNameError:
		data.DomainKey = "NXDomain" // NXDomain (3)
	case dns.RcodeNotImplemented:
		data.DomainKey = "NotImp" // NotImp (4)
	case dns.RcodeRefused:
		data.DomainKey = "Refused" // Refused (5)
	default:
		data.DomainKey = "Code: " + strconv.Itoa(rcode)
	}
	data.AuthenticatedData = r.AuthenticatedData

	return data, err
}

// ------------------------------- TLSA -------------------------

type tlsa struct {
	Record            string      `json:"record"`
	AuthenticatedData bool        `json:"authenticated_data"`
	TLSA              []*dns.TLSA `json:"tlsarecord"`
}

func getTLSA(host string, nameserver string) (*tlsa, error) {
	data := new(tlsa)
	data.Record = "_25._tcp." + host

	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(data.Record), dns.TypeTLSA)
	m.RecursionDesired = true
	m.SetEdns0(4096, true)

	r, _, err := c.Exchange(m, net.JoinHostPort(nameserver, "53"))
	if r == nil {
		return nil, err
	}

	if r.Rcode != dns.RcodeSuccess {
		err = errors.New("TLSA record lookup not successful")
		return nil, err
	}

	data.AuthenticatedData = r.AuthenticatedData

	for _, r := range r.Answer {
		if a, ok := r.(*dns.TLSA); ok {
			data.TLSA = append(data.TLSA, a)
		}
	}

	return data, nil
}
