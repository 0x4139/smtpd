Go smtpd [![GoDoc](https://godoc.org/github.com/marcinwyszynski/smtpd?status.png)](https://godoc.org/github.com/marcinwyszynski/smtpd)
========

Package smtpd implements an SMTP server in golang.
This is a fork of bitbucket.org/chrj/smtpd 

Features
--------

* STARTTLS (using `crypto/tls`)
* Authentication (PLAIN/LOGIN, only after STARTTLS)
* XCLIENT (for running behind a proxy)
* Connection, HELO, sender and recipient checks for rejecting e-mails using callbacks
* Configurable limits for: connection count, message size and recipient count
* Hands incoming e-mail off to a configured callback function
