(use binary.pack)
(use gauche.net)
(use gauche.uvector)

(define (dhcp6-msg)
  (string-append (pack "CC3" '(11 1 2 3) :to-string? #t)
		 (pack "nnn" '(6 2 23) :to-string? #t)))

(let1 sock (make-socket AF_INET6 SOCK_DGRAM)
  (socket-setsockopt sock SOL_SOCKET SO_REUSEADDR 1)
  (socket-bind sock (car (make-sockaddrs "::" 546 'udp)))

  (socket-sendto sock (dhcp6-msg)
		 (car (make-sockaddrs "ff02::1:2%en0" 547 'udp)))
  )
