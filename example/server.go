// Copyright 2016 Michal Witkowski. All Rights Reserved.
// See LICENSE for licensing terms.

package main

import (
	"flag"
	"log"
	"net"
	"net/http"

	"crypto/tls"
	"fmt"

	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/net/context/ctxhttp"
	_ "golang.org/x/net/trace"
	"github.com/mwitkow/go-conntrack"
)

var (
	port            = flag.Int("port", 9090, "whether to use tls or not")
	useTls          = flag.Bool("tls", true, "Whether to use TLS and HTTP2.")
	tlsCertFilePath = flag.String("tls_cert_file", "certs/localhost.crt", "Path to the CRT/PEM file.")
	tlsKeyFilePath  = flag.String("tls_key_file", "certs/localhost.key", "Path to the private key file.")
)

func main() {
	flag.Parse()

	// Make sure all outbound connections use the wrapped dialer.
	http.DefaultTransport.(*http.Transport).DialContext = conntrack.NewDialContextFunc(
		conntrack.DialWithTracing(),
		conntrack.DialWithDialer(&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}),
	)
	// Since we're using a dynamic name, let's preregister it with prometheus.
	conntrack.PreRegisterDialerMetrics("google")

	handler := func(resp http.ResponseWriter, req *http.Request) {
		resp.WriteHeader(http.StatusOK)
		resp.Header().Add("Content-Type", "application/json")
		resp.Write([]byte(`{"msg": "hello"}`))
		callCtx := conntrack.DialNameToContext(req.Context(), "google")
		_, err := ctxhttp.Get(callCtx, http.DefaultClient, "https://www.google.comx")
		log.Printf("Google reached with err: %v", err)
		log.Printf("Got request: %v", req)
	}

	http.DefaultServeMux.Handle("/", http.HandlerFunc(handler))
	http.DefaultServeMux.Handle("/metrics", prometheus.Handler())

	httpServer := http.Server{
		Handler: http.DefaultServeMux,
	}
	var httpListener net.Listener
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	listener = conntrack.NewListener(listener, conntrack.TrackWithTracing())
	if !*useTls {
		httpListener = listener
	} else {
		tlsConfig, err := tlsConfigForCert(*tlsCertFilePath, *tlsKeyFilePath)
		if err != nil {
			log.Fatalf("Failed configuring TLS: %v", err)
		}
		log.Printf("Listening with TLS")
		//httpServer.TLSConfig = tlsConfig
		tlsListener := tls.NewListener(listener, tlsConfig)
		httpListener = tlsListener

	}
	//httpListener.Addr()
	log.Printf("Listening on: %s", listener.Addr().String())
	if err := httpServer.Serve(httpListener); err != nil {
		log.Fatalf("Failed listning: %v", err)
	}
}

// tlsConfigForCert is needed as it duplicates ListenAndServeTLS, but for a listener.
func tlsConfigForCert(certFile string, keyFile string) (*tls.Config, error) {
	var err error
	config := new(tls.Config)
	config, err = tlsEnableHttp2(config)
	if err != nil {
		return nil, err
	}
	// Make sure http1.1 is *after* h2.
	config.NextProtos = append(config.NextProtos, "http/1.1")

	config.Certificates = make([]tls.Certificate, 1)
	config.Certificates[0], err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return tlsEnableHttp2(config)
}

//tlsEnableHttp2 performs what http2ConfigureServer does privately.
func tlsEnableHttp2(config *tls.Config) (*tls.Config, error) {
	if config.CipherSuites != nil {
		// If they already provided a CipherSuite list, return
		// an error if it has a bad order or is missing
		// ECDHE_RSA_WITH_AES_128_GCM_SHA256.
		const requiredCipher = tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
		haveRequired := false
		for _, cs := range config.CipherSuites {
			if cs == requiredCipher {
				haveRequired = true
			}
		}
		if !haveRequired {
			return nil, fmt.Errorf("http2: TLSConfig.CipherSuites is missing HTTP/2-required TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
		}
	}

	config.PreferServerCipherSuites = true

	haveNPN := false
	for _, p := range config.NextProtos {
		if p == "h2" {
			haveNPN = true
			break
		}
	}
	if !haveNPN {
		config.NextProtos = append(config.NextProtos, "h2")
	}
	config.NextProtos = append(config.NextProtos, "h2-14")
	return config, nil
}
