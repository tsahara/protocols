(use gauche.net)
(use gauche.uvector)

(use femto.dns)

(define *bind-port* 53)

(define (send-dns-packet buf len)
  (let ((sin  (make <sockaddr-in> :host (dns-server) :port 53))
	(sock (make-socket PF_INET SOCK_DGRAM))
	(rbuf (make-u8vector 4096)))
    (socket-connect sock sin)
    (socket-send sock (u8vector-copy buf 0 len))
    (receive (recvlen peeraddr)
	(socket-recvfrom! sock rbuf '(#t))
     (show-dns-packet rbuf recvlen)
     (u8vector-copy rbuf 0 recvlen))))

(dns-read-resolv-conf)
(let ((q (make-dns-query "www.iij.ad.jp" 46)))
  (send-dns-packet q (u8vector-length q)))
