// Package smtpd implements an SMTP server with support for STARTTLS,
// authentication (PLAIN/LOGIN), XCLIENT and optional restrictions on the
// different stages of the SMTP session.
package smtpd

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"time"
)

// Server defines the parameters for running the SMTP server
type Server struct {
	// Server hostname. (default: "localhost.localdomain")
	Hostname string
	// Initial server banner. (default: "<hostname> ESMTP ready.")
	WelcomeMessage string

	// Socket timeout for read operations. (default: 60s)
	ReadTimeout time.Duration
	// Socket timeout for write operations. (default: 60s)
	WriteTimeout time.Duration
	// Socket timeout for DATA command (default: 5m)
	DataTimeout time.Duration

	// Max concurrent connections, use -1 to disable. (default: 100)
	MaxConnections int
	// Max message size in bytes. (default: 10240000)
	MaxMessageSize int64
	// Max RCPT TO calls for each envelope. (default: 100)
	MaxRecipients int

	// New e-mails are handed off to this function.
	// Can be left empty for a NOOP server.
	// If an error is returned, it will be reported in the SMTP session.
	Handler func(peer Peer, env Envelope) error

	// Enable various checks during the SMTP session.
	// Can be left empty for no restrictions.
	// If an error is returned, it will be reported in the SMTP session.
	// Use the Error struct for access to error codes.
	ConnectionChecker func(peer Peer) error              // Called upon new connection.
	HeloChecker       func(peer Peer, name string) error // Called after HELO/EHLO.
	SenderChecker     func(peer Peer, addr string) error // Called after MAIL FROM.
	RecipientChecker  func(peer Peer, addr string) error // Called after each RCPT TO.

	// Enable PLAIN/LOGIN authentication, only available after STARTTLS.
	// Can be left empty for no authentication support.
	Authenticator func(peer Peer, username, password string) error

	// BlackHole is an optimization that allows quietly sending all the
	// incoming message to the big /dev/null in the sky while still
	// maintaining a polite conversation with the client. This behaviour is
	// triggered when the function is set and returns true. In that case the
	// Handler function is not invoked at all. Please note that the
	// Envelope at this stage has its Data field empty.
	BlackHole func(peer Peer, env Envelope) bool

	EnableXCLIENT bool // Enable XCLIENT support (default: false)

	TLSConfig *tls.Config // Enable STARTTLS support.
	ForceTLS  bool        // Force STARTTLS usage.
}

// Protocol represents the protocol used in the SMTP session
type Protocol string

const (
	// SMTP protocol name
	SMTP Protocol = "SMTP"
	// ESMTP protocol name
	ESMTP = "ESMTP"
)

// Peer represents the client connecting to the server
type Peer struct {
	// Server name used in HELO/EHLO command
	HeloName string
	// Username from authentication, if authenticated
	Username string
	// Password from authentication, if authenticated
	Password string
	// Protocol used, SMTP or ESMTP
	Protocol Protocol
	// A copy of Server.Hostname
	ServerName string
	// Network address
	Addr net.Addr
	// TLS Connection details, if on TLS
	TLS *tls.ConnectionState
}

// ListenAndServe starts the SMTP server and listens on the address provided
func (srv *Server) ListenAndServe(addr string) error {
	srv.configureDefaults()
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return srv.Serve(l)
}

// Serve starts the SMTP server and listens on the Listener provided
func (srv *Server) Serve(l net.Listener) error {
	srv.configureDefaults()
	defer l.Close()
	var limiter chan struct{}
	if srv.MaxConnections > 0 {
		limiter = make(chan struct{}, srv.MaxConnections)
	} else {
		limiter = nil
	}
	for {
		conn, e := l.Accept()
		if e != nil {
			if ne, ok := e.(net.Error); ok && ne.Temporary() {
				time.Sleep(time.Second)
				continue
			}
			return e
		}
		session := srv.newSession(conn)
		if limiter != nil {
			go func() {
				select {
				case limiter <- struct{}{}:
					session.serve()
					<-limiter
				default:
					session.reject()
				}
			}()
		} else {
			go session.serve()
		}
	}
}

func (srv *Server) configureDefaults() {
	if srv.MaxMessageSize == 0 {
		srv.MaxMessageSize = 10240000
	}
	if srv.MaxConnections == 0 {
		srv.MaxConnections = 100
	}
	if srv.MaxRecipients == 0 {
		srv.MaxRecipients = 100
	}
	if srv.ReadTimeout == 0 {
		srv.ReadTimeout = time.Second * 60
	}
	if srv.WriteTimeout == 0 {
		srv.WriteTimeout = time.Second * 60
	}
	if srv.DataTimeout == 0 {
		srv.DataTimeout = time.Minute * 5
	}
	if srv.ForceTLS && srv.TLSConfig == nil {
		log.Fatal("Cannot use ForceTLS with no TLSConfig")
	}
	if srv.Hostname == "" {
		srv.Hostname = "localhost.localdomain"
	}
	if srv.WelcomeMessage == "" {
		srv.WelcomeMessage = fmt.Sprintf(
			"%s ESMTP ready.",
			srv.Hostname,
		)
	}
}
