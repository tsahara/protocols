(use gauche.net)

(define (read-uint16 port)
  (let* ((a (read-byte port))
	 (b (read-byte port)))
    (if (or (eof-object? a) (eof-object? b))
	(error "eof read")
	(+ (* a 256) b))))

(define (read-uint32 port)
  (let* ((a (read-byte port))
	 (b (read-byte port))
	 (c (read-byte port))
	 (d (read-byte port)))
    (if (or (eof-object? a)
	    (eof-object? b)
	    (eof-object? c)
	    (eof-object? d))
	(error "eof read")
	(+ (* a 256 256 256)
	   (* b 256 256)
	   (* c 256)
	   d))))

(define (read-mp-int port)
  (let ((bits (read-uint16 port)))
    (if (= bits 0)
	(cons 0 "")
	(cons bits (read-block port (quotient (+ bits 7) 8))))))

(define (ssh-type-string type)
  (define strlist
    '("SSH_MSG_NONE"
      "SSH_MSG_DISCONNECT"
      "SSH_SMSG_PUBLIC_KEY"))
  (if (< type (length strlist))
      (list-ref strlist type)
      (number->string type)))

(define-class <ssh-msg> ()
   ((type :init-keyword :type)
    (len :init-keyword :len)
    (data :init-keyword :data)
    ))

(define-method dump ((msg <ssh-msg>))
  (format #t "type: ~a\n" (slot-ref msg 'type))
  (format #t "len: ~a\n" (slot-ref msg 'len)))

(define-class <ssh-msg-none> (<ssh-msg>)
  ())

(define-class <ssh-msg-disconnect> (<ssh-msg>)
  ())

(define-class <ssh-smsg-public-key> (<ssh-msg>)
  ((anti-spoofing-cookie)
   (server-key-bits)
   (server-key-public-exponent)
   (server-key-public-modulus)
   (host-key-bits)
   (host-key-public-exponent)
   (host-key-public-modulus)
   (protocol-flags)
   (supported-ciphers-mask)
   (supported-authentications-mask)
   ))

(define-method initialize ((msg <ssh-smsg-public-key>))
  (let1 p (open-input-string (slot-ref msg 'data))
    (slot-set! msg 'anti-spoofing-cookie (read-block p 8))
    (slot-set! msg 'server-key-bits (read-uint32 p))
    (slot-set! msg 'server-key-public-exponent (read-mp-int p))
    (slot-set! msg 'server-key-public-modulus (read-mp-int p))
    (slot-set! msg 'host-key-bits (read-uint32 p))
    (slot-set! msg 'host-key-public-exponent (read-mp-int p))
    (slot-set! msg 'host-key-public-modulus (read-mp-int p))
    (slot-set! msg 'protocol-flags (read-uint32 p))
    (slot-set! msg 'supported-ciphers-mask (read-uint32 p))
    (slot-set! msg 'supported-authentications-mask (read-uint32 p))
  ))

(define-method dump ((msg <ssh-smsg-public-key>))
  (format #t "server-key-bits: ~a\n" (slot-ref msg 'server-key-bits))
  (format #t "host-key-bits: ~a\n" (slot-ref msg 'host-key-bits)))

(define-class <ssh-cmsg-session-key> (<ssh-msg>)
  ())

(define msgmap
  (list <ssh-msg-none>
	<ssh-msg-disconnect>
	<ssh-smsg-public-key>
	<ssh-cmsg-session-key>
	))

(define (make-ssh-message type len data)
  (let1 klass (list-ref msgmap type)
    (make klass :type type :len len :data data)))

(define (ssh-read-packet port)
  (define (read-padding port len)
    (let1 skiplen (- 8 (modulo len 8))
      (format #t "skip ~d bytes\n" skiplen)
      (read-block skiplen port)))
  (define (check-crc))
  (let* ((len (read-uint32 port))
	 (padding (read-padding port len))
	 (type (read-byte port))
	 (data (read-block (- len 5) port))
	 (crc (read-uint32 port)))
	 (check-crc)
    (make-ssh-message type len data)))

(define (ssh-login)
  (define hostname "localhost")
  (define port 22)
  (call-with-client-socket
      (make-client-socket 'inet hostname port)
    (lambda (in out)
      (format #t "server version string: ~a\n" (read-line in))
      (format out "SSH-1.3-femto_ssh_0.1\n")
      (dump (ssh-read-packet in))
      )))

(ssh-login)
