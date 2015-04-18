package smtpd

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

type cmdHandler func(*session, command)

var (
	cmdMap = map[string]cmdHandler{
		"HELO":     (*session).handleHELO,
		"EHLO":     (*session).handleEHLO,
		"MAIL":     (*session).handleMAIL,
		"RCPT":     (*session).handleRCPT,
		"STARTTLS": (*session).handleSTARTTLS,
		"DATA":     (*session).handleDATA,
		"RSET":     (*session).handleRSET,
		"QUIT":     (*session).handleQUIT,
		"AUTH":     (*session).handleAUTH,
		"XCLIENT":  (*session).handleXCLIENT,
		"NOOP":     (*session).goAhead,
	}

	authMap = map[string]cmdHandler{
		"LOGIN": (*session).authLOGIN,
		"PLAIN": (*session).authPLAIN,
	}
)

type command struct {
	line   string
	action string
	fields []string
	params []string
}

func parseLine(line string) (cmd command) {
	cmd.line = line
	cmd.fields = strings.Fields(line)
	if len(cmd.fields) > 0 {
		cmd.action = strings.ToUpper(cmd.fields[0])
		if len(cmd.fields) > 1 {
			cmd.params = strings.Split(cmd.fields[1], ":")
		}
	}
	return
}

type session struct {
	server *Server

	peer     Peer
	envelope *Envelope

	conn net.Conn

	reader  *bufio.Reader
	writer  *bufio.Writer
	scanner *bufio.Scanner

	tls bool
}

func (srv *Server) newSession(c net.Conn) (s *session) {
	s = &session{
		server: srv,
		conn:   c,
		reader: bufio.NewReader(c),
		writer: bufio.NewWriter(c),
		peer: Peer{
			Addr:       c.RemoteAddr(),
			ServerName: srv.Hostname,
		},
	}
	s.scanner = bufio.NewScanner(s.reader)
	return
}

func (s *session) serve() {
	defer s.close()
	s.welcome()
	for {
		for s.scanner.Scan() {
			s.handle(s.scanner.Text())
		}
		err := s.scanner.Err()
		if err == bufio.ErrTooLong {
			s.reply(StatusSyntaxError, "Line too long")
			// Advance reader to the next newline
			s.reader.ReadString('\n')
			s.scanner = bufio.NewScanner(s.reader)
			// Reset and have the client start over.
			s.reset()
			continue
		}
		break
	}
}

func (s *session) reject() {
	s.reply(StatusServiceNotAvailable, "Too busy. Try again later.")
	s.close()
}

func (s *session) reset() {
	s.envelope = nil
}

func (s *session) welcome() {
	if s.server.ConnectionChecker == nil {
		s.reply(StatusServiceReady, s.server.WelcomeMessage)
		return
	}
	if err := s.server.ConnectionChecker(s.peer); err != nil {
		s.reportError(err)
		s.close()
	}
}

func (s *session) reply(code StatusCode, message string) {
	fmt.Fprintf(s.writer, "%d %s\r\n", code, message)
	s.flush()
}

func (s *session) flush() {
	s.conn.SetWriteDeadline(
		time.Now().Add(s.server.WriteTimeout))
	s.writer.Flush()
	s.conn.SetReadDeadline(
		time.Now().Add(s.server.ReadTimeout))
}

func (s *session) reportError(err error) {
	if smtpdError, ok := err.(Error); ok {
		s.reply(smtpdError.Code, smtpdError.Message)
		return
	}
	s.reply(StatusLocalError, err.Error())
}

func (s *session) extensions() []string {
	extensions := []string{
		fmt.Sprintf("SIZE %d", s.server.MaxMessageSize),
		"8BITMIME",
		"PIPELINING",
	}
	if s.server.EnableXCLIENT {
		extensions = append(extensions, "XCLIENT")
	}
	if s.server.TLSConfig != nil && !s.tls {
		extensions = append(extensions, "STARTTLS")
	}
	if s.server.Authenticator != nil && s.tls {
		extensions = append(extensions, "AUTH PLAIN LOGIN")
	}
	return extensions
}

func (s *session) deliver() error {
	if s.server.Handler != nil {
		return s.server.Handler(s.peer, *s.envelope)
	}
	return nil
}

func (s *session) close() {
	defer s.conn.Close()
	s.writer.Flush()
	time.Sleep(200 * time.Millisecond)
}

func (s *session) handle(line string) {
	cmd := parseLine(line)
	action, exists := cmdMap[cmd.action]
	if !exists {
		s.reply(StatusCommandNotImplemented, "Unsupported command")
		return
	}
	action(s, cmd)
}

func (s *session) handleHELO(cmd command) {
	if len(cmd.fields) < 2 {
		s.reply(StatusParameterNotImplemented, "Missing parameter")
		return
	}
	if s.peer.HeloName != "" {
		s.reset() // Reset envelope in case of duplicate HELO
	}
	if s.server.HeloChecker != nil {
		err := s.server.HeloChecker(s.peer, cmd.fields[1])
		if err != nil {
			s.reportError(err)
			return
		}
	}
	s.peer.HeloName = cmd.fields[1]
	s.peer.Protocol = SMTP
	s.goAhead(cmd)
}

func (s *session) handleEHLO(cmd command) {
	if len(cmd.fields) < 2 {
		s.reply(StatusParameterNotImplemented, "Missing parameter")
		return
	}
	if s.peer.HeloName != "" {
		// Reset envelope in case of duplicate EHLO
		s.reset()
	}
	if s.server.HeloChecker != nil {
		err := s.server.HeloChecker(s.peer, cmd.fields[1])
		if err != nil {
			s.reportError(err)
			return
		}
	}
	s.peer.HeloName = cmd.fields[1]
	s.peer.Protocol = ESMTP
	fmt.Fprintf(s.writer, "250-%s\r\n", s.server.Hostname)
	extensions := s.extensions()
	if len(extensions) > 1 {
		for _, ext := range extensions[:len(extensions)-1] {
			fmt.Fprintf(s.writer, "250-%s\r\n", ext)
		}
	}
	s.reply(StatusOK, extensions[len(extensions)-1])
}

func (s *session) handleMAIL(cmd command) {
	if !s.ensureHELO() {
		return
	}
	if !s.tls && s.server.ForceTLS {
		s.reply(
			StatusBadSequence,
			"Please turn on TLS by issuing a STARTTLS command.",
		)
		return
	}
	if s.envelope != nil {
		s.reply(StatusBadSequence, "Duplicate MAIL")
		return
	}
	addr, err := parseAddress(cmd.params[1])
	if err != nil {
		s.reply(
			StatusMailboxNameNotAllowed,
			"Ill-formatted e-mail address",
		)
		return
	}
	if s.server.SenderChecker != nil {
		err = s.server.SenderChecker(s.peer, addr)
		if err != nil {
			s.reportError(err)
			return
		}
	}
	s.envelope = &Envelope{Sender: addr}
	s.goAhead(cmd)
}

func (s *session) handleRCPT(cmd command) {
	if s.envelope == nil {
		s.reply(StatusSyntaxError, "Missing MAIL FROM command.")
		return
	}
	if len(s.envelope.Recipients) >= s.server.MaxRecipients {
		s.reply(StatusInsufficientStorage, "Too many recipients")
		return
	}
	addr, err := parseAddress(cmd.params[1])
	if err != nil {
		s.reply(StatusSyntaxError, "Ill-formatted e-mail address")
		return
	}
	if s.server.RecipientChecker != nil {
		err = s.server.RecipientChecker(s.peer, addr)
		if err != nil {
			s.reportError(err)
			return
		}
	}
	s.envelope.Recipients = append(s.envelope.Recipients, addr)
	s.goAhead(cmd)
}

func (s *session) handleSTARTTLS(cmd command) {
	if s.tls {
		s.reply(StatusSyntaxError, "Already running in TLS")
		return
	}
	if s.server.TLSConfig == nil {
		s.reply(StatusCommandNotImplemented, "TLS not supported")
		return
	}
	tlsConn := tls.Server(s.conn, s.server.TLSConfig)
	s.reply(StatusServiceReady, "Go ahead")
	if err := tlsConn.Handshake(); err != nil {
		s.reply(StatusMailboxPermanentlyUnavailable, "Handshake error")
		return
	}

	// Reset envelope as a new EHLO/HELO is required after STARTTLS
	s.reset()

	// Reset deadlines on the underlying connection before I replace it
	// with a TLS connection
	s.conn.SetDeadline(time.Time{})

	// Replace connection with a TLS connection
	s.conn = tlsConn
	s.reader = bufio.NewReader(tlsConn)
	s.writer = bufio.NewWriter(tlsConn)
	s.scanner = bufio.NewScanner(s.reader)
	s.tls = true

	// Save connection state on peer
	state := tlsConn.ConnectionState()
	s.peer.TLS = &state

	// Flush the connection to set new timeout deadlines
	s.flush()
	return
}

func (s *session) handleDATA(cmd command) {
	if s.envelope == nil || len(s.envelope.Recipients) == 0 {
		s.reply(StatusSyntaxError, "Missing RCPT TO command.")
		return
	}
	s.reply(
		StatusStartMailInput,
		"Go ahead. End your data with <CR><LF>.<CR><LF>",
	)
	s.conn.SetDeadline(time.Now().Add(s.server.DataTimeout))
	data := &bytes.Buffer{}
	reader := textproto.NewReader(s.reader).DotReader()
	_, err := io.CopyN(data, reader, int64(s.server.MaxMessageSize))
	if err == io.EOF {
		// EOF was reached before MaxMessageSize
		// Accept and deliver message
		s.envelope.Data = data.Bytes()
		if err := s.deliver(); err != nil {
			s.reportError(err)
		} else {
			s.reply(StatusOK, "Thank you.")
		}
		s.reset()
	}
	if err != nil {
		return // Network error, ignore
	}
	// Discard the rest and report an error.
	_, err = io.Copy(ioutil.Discard, reader)
	if err != nil {
		return // Network error, ignore
	}
	s.reply(StatusExceededStorageAllocation, fmt.Sprintf(
		"Message exceeded max message size of %d bytes",
		s.server.MaxMessageSize,
	))
	s.reset()
}

func (s *session) handleRSET(cmd command) {
	s.reset()
	s.goAhead(cmd)
}

func (s *session) handleQUIT(cmd command) {
	s.reply(StatusServiceClosing, "OK, bye")
	s.close()
}

func (s *session) handleAUTH(cmd command) {
	if s.server.Authenticator == nil {
		s.reply(StatusCommandNotImplemented, "AUTH not supported.")
		return
	}
	if !s.ensureHELO() {
		return
	}
	if !s.tls {
		s.reply(
			StatusSyntaxError,
			"Cannot AUTH in plain text mode. Use STARTTLS.",
		)
		return
	}
	mechanism := strings.ToUpper(cmd.fields[1])
	action, exists := authMap[mechanism]
	if !exists {
		s.reply(
			StatusCommandNotImplemented,
			"Unknown authentication mechanism",
		)
		return
	}
	action(s, cmd)
}

func (s *session) handleXCLIENT(cmd command) {
	if !s.server.EnableXCLIENT {
		s.reply(
			StatusMailboxPermanentlyUnavailable,
			"XCLIENT not enabled",
		)
		return
	}
	var (
		newHeloName = ""
		newAddr     net.IP
		newTCPPort  uint64
		newUsername = ""
		newProto    Protocol
	)
	for _, item := range cmd.fields[1:] {
		parts := strings.Split(item, "=")
		if len(parts) != 2 {
			s.errDecodingCommand()
			return
		}
		name, value := parts[0], parts[1]
		switch name {
		case "NAME":
			// Unused in smtpd package
			continue
		case "HELO":
			newHeloName = value
			continue
		case "ADDR":
			newAddr = net.ParseIP(value)
			continue
		case "PORT":
			var err error
			newTCPPort, err = strconv.ParseUint(value, 10, 16)
			if err != nil {
				s.errDecodingCommand()
				return
			}
			continue
		case "LOGIN":
			newUsername = value
			continue
		case "PROTO":
			if value == "SMTP" {
				newProto = SMTP
			} else if value == "ESMTP" {
				newProto = ESMTP
			}
			continue
		default:
			s.errDecodingCommand()
			return
		}
	}
	tcpAddr, ok := s.peer.Addr.(*net.TCPAddr)
	if !ok {
		s.reply(
			StatusCommandNotImplemented,
			"Unsupported network connection",
		)
		return
	}
	if newHeloName != "" {
		s.peer.HeloName = newHeloName
	}
	if newAddr != nil {
		tcpAddr.IP = newAddr
	}
	if newTCPPort != 0 {
		tcpAddr.Port = int(newTCPPort)
	}
	if newUsername != "" {
		s.peer.Username = newUsername
	}
	if newProto != "" {
		s.peer.Protocol = newProto
	}
	s.welcome()
}

func (s *session) authLOGIN(cmd command) {
	s.reply(StatusProvideCredentials, "VXNlcm5hbWU6")
	if !s.scanner.Scan() {
		return
	}
	byteUsername, err := base64.StdEncoding.DecodeString(s.scanner.Text())
	if err != nil {
		s.errDecodingCredentials()
		return
	}
	s.reply(StatusProvideCredentials, "UGFzc3dvcmQ6")
	if !s.scanner.Scan() {
		return
	}
	bytePassword, err := base64.StdEncoding.DecodeString(s.scanner.Text())
	if err != nil {
		s.errDecodingCredentials()
		return
	}
	s.authenticate(string(byteUsername), string(bytePassword))
}

func (s *session) authPLAIN(cmd command) {
	auth := ""
	if len(cmd.fields) < 3 {
		s.reply(StatusProvideCredentials, "Give me your credentials")
		if !s.scanner.Scan() {
			return
		}
		auth = s.scanner.Text()
	} else {
		auth = cmd.fields[2]
	}
	data, err := base64.StdEncoding.DecodeString(auth)
	if err != nil {
		s.errDecodingCredentials()
		return
	}
	parts := bytes.Split(data, []byte{0})
	if len(parts) != 3 {
		s.errDecodingCredentials()
		return
	}
	s.authenticate(string(parts[1]), string(parts[2]))
}

func (s *session) goAhead(cmd command) {
	s.reply(StatusOK, "Go ahead")
}

func (s *session) authenticate(user, pass string) {
	if err := s.server.Authenticator(s.peer, user, pass); err != nil {
		s.reportError(err)
		return
	}
	s.peer.Username = user
	s.peer.Password = pass
	s.reply(StatusAuthenticated, "OK, you are now authenticated")
}

func (s *session) errDecodingCommand() {
	s.reply(StatusSyntaxError, "Couldn't decode the command.")
}

func (s *session) errDecodingCredentials() {
	s.reply(StatusSyntaxError, "Couldn't decode your credentials.")
}

func (s *session) ensureHELO() bool {
	if s.peer.HeloName != "" {
		return true
	}
	s.reply(StatusBadSequence, "Please introduce yourself first.")
	return false
}
