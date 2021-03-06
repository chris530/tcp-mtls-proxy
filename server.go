package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/pkg/profile"
	"io/ioutil"
	"net"
	"os"
        "os/signal"
        "syscall"
)

var local string
var nounsecure string
var localmtlsport string
var localport string
var localmtls string
var profileapp string
var remoteAddressandPort string
var byteread int = 1024 * 1024
var certdirpath string

func main() {
	certdirpath = os.Getenv("certdirpath")
	nounsecure = os.Getenv("nounsecure")
	localport = os.Getenv("localport")
	localmtlsport = os.Getenv("localmtlsport")
	local = "localhost:" + localport
	localmtls = "localhost:" + localmtlsport
	remoteAddressandPort = os.Getenv("remote_addr_and_port")
	profileapp = os.Getenv("profile")

	if profileapp == "yes" {
		defer profile.Start(profile.MemProfile).Stop()
	}
 
        if localmtlsport == "" && localport == "" {
                panic("Nothing is set to listen, you need either a unsecure, secure or both port to listen on")
        }
  
	if localport == "" && nounsecure != "true" {
		panic("Set the environment variable localport=<port>")
	} else {
            if nounsecure != "true" {
		fmt.Println("unsecure connection is listening on : ", local)
            }
	}

	if remoteAddressandPort == "" {
		panic("Set the environment variable remote_addr_and_port=<remote addr>:<port>")
	} else {
		fmt.Println("backend is listening on : ", remoteAddressandPort)
	}

	// Use mTLS ?

	if localmtlsport != "" {
    
                fmt.Println("secure mTLS is listening on : ", localmtls)

		if certdirpath == "" {

			fmt.Println("certdirpath environment variable empty so using server.crt, server.key and ca.crt for certs")

		} else {

			fmt.Println("using certs " + certdirpath + "server.crt" + " " + certdirpath + "server.key" + "  " + certdirpath + "ca.crt for mTLS")

		}

		rootPEM, err := ioutil.ReadFile(certdirpath + "ca.crt")
		cert, err := tls.LoadX509KeyPair(certdirpath+"server.crt", certdirpath+"server.key")
		if err != nil {
			panic("Error loading server.crt, server.key or ca.crt")
		}

		roots := x509.NewCertPool()
		ok := roots.AppendCertsFromPEM([]byte(string(rootPEM)))
		if !ok {
			panic("error with appending cert")
		}

		config := tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}

		listenermtls, err := tls.Listen("tcp", localmtls, &config)
		if err != nil {
			panic(err)
		}

		go func() {

			for {
				conn1, err := listenermtls.Accept()
				if err != nil {
					break
				}

				go mtlsproxyConnection(conn1)
			}
		}()
	}

	// Unsecure server

        if nounsecure != "" {
  
           fmt.Println("unsecure is not listening")
           
           quitChannel := make(chan os.Signal, 1)
           signal.Notify(quitChannel, syscall.SIGINT, syscall.SIGTERM)
           <-quitChannel
           fmt.Println("Adios!")           

        } else {

	lAddr, err := net.ResolveTCPAddr("tcp", local)
	if err != nil {
		panic(err)
	}

	listener, err := net.ListenTCP("tcp", lAddr)
	if err != nil {
		panic(err)
	}

	for {
		conn2, err := listener.AcceptTCP()
		if err != nil {
			break
		}

		go proxyConnection(conn2)
	}

        }

}

func mtlsproxyConnection(conn net.Conn) {

	rAddr, err := net.ResolveTCPAddr("tcp", remoteAddressandPort)
	if err != nil {
		panic(err)
	}

	rConn, err := net.DialTCP("tcp", nil, rAddr)
	if err != nil {
		panic(err)
	}

	defer rConn.Close()

	// Request loop
	go func() {
		for {
			data := make([]byte, byteread)
			n, err := conn.Read(data)
			if err != nil {
				break
			}
			rConn.Write(data[:n])
		}
	}()

	// Response loop
	for {
		data := make([]byte, byteread)
		n, err := rConn.Read(data)
		if err != nil {
			break
		}
		conn.Write(data[:n])
	}

}

func proxyConnection(conn *net.TCPConn) {

	rAddr, err := net.ResolveTCPAddr("tcp", remoteAddressandPort)
	if err != nil {
		panic(err)
	}

	rConn, err := net.DialTCP("tcp", nil, rAddr)
	if err != nil {
		panic(err)
	}

	defer rConn.Close()

	// Request loop
	go func() {
		for {
			data := make([]byte, byteread)
			n, err := conn.Read(data)
			if err != nil {
				break
			}
			rConn.Write(data[:n])
		}
	}()

	// Response loop
	for {
		data := make([]byte, byteread)
		n, err := rConn.Read(data)
		if err != nil {
			break
		}
		conn.Write(data[:n])
	}

}
