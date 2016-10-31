package main

import (
	"flag"
	"log"
	"net"
	"net/http"

	"crypto/tls"
	"fmt"
)

var (
	port            = flag.Int("port", 9090, "whether to use tls or not")
	useTls          = flag.Bool("tls", true, "Whether to use TLS and HTTP2.")
	tlsCertFilePath = flag.String("tls_cert_file", "certs/localhost.crt", "Path to the CRT/PEM file.")
	tlsKeyFilePath  = flag.String("tls_key_file", "certs/localhost.key", "Path to the private key file.")
)

func main() {
	flag.Parse()

	handler := func(resp http.ResponseWriter, req *http.Request) {
		resp.WriteHeader(http.StatusOK)
		resp.Header().Add("Content-Type", "application/json")
		resp.Write([]byte(`{"msg": "hello"}`))
		log.Printf("Got request: %v", req)
	}

	httpServer := http.Server{
		Handler: http.HandlerFunc(handler),
	}
	var httpListener net.Listener
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	if !*useTls {
		httpListener = listener
	} else {
		tlsConfig, err := tlsConfigForCert(*tlsCertFilePath, *tlsKeyFilePath)
		if err != nil {
			log.Fatalf("Failed configuring TLS: %v", err)
		}
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
