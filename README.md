# Go tracing and monitoring (Prometheus) for `net.Conn`

[![Travis Build](https://travis-ci.org/mwitkow/go-conntrack.svg)](https://travis-ci.org/mwitkow/go-conntrack)
[![Go Report Card](https://goreportcard.com/badge/github.com/mwitkow/go-conntrack)](http://goreportcard.com/report/mwitkow/go-conntrack)
[![GoDoc](http://img.shields.io/badge/GoDoc-Reference-blue.svg)](https://godoc.org/github.com/mwitkow/go-conntrack)
[![Apache 2.0 License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

[Prometheus](https://prometheus.io/) monitoring and [`x/net/trace`](https://godoc.org/golang.org/x/net/trace#EventLog) tracing wrappers `net.Conn`, both inbound (`net.Listener`) and outbound (`net.Dialer`).

## Why?

Go standard library does a great job of doing "the right" things with your connections: `http.Transport` pools outbound ones, and `http.Server` sets good *Keep Alive* defaults.
However, it is still easy to get it wrong, see the excellent [*The complete guide to Go net/http timeouts*](https://blog.cloudflare.com/the-complete-guide-to-golang-net-http-timeouts/). 

That's why you should be able to monitor (using Prometheus) how many connections your Go frontend servers have inbound, and how big are the connection pools to your backends.
