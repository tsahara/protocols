#!/usr/bin/env gosh

(use gauche.net)

(define (main args)
  (let ((sock (make-socket AF_INET SOCK_DGRAM)))
    (socket-connect sock (make <sockaddr-in> :host "127.0.0.1" :port 1616))
    (socket-send sock
		 #u8(#x30 #x29 #x02 #x01 #x00 #x04 #x06 #x70 #x75 #x62
			  #x6c #x69 #x63 #xa0 #x1c #x02 #x04 #x0b #x70 #x7b
			  #x32 #x02 #x01 #x00 #x02 #x01 #x00 #x30 #x0e #x30
			  #x0c #x06 #x08 #x2b #x06 #x01 #x02 #x01 #x01 #x01
			  #x00 #x05 #x00))
    ))
