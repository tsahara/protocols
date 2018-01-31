(use binary.io)
(use gauche.net)
(use gauche.uvector)

(define read-uint32 read-u32)

(define (read-u32be port)
  (read-u32 port 'big-endian))

(define (read-mp-int port)
  (let ((bits (read-u16 port)))
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
  (let* ((packet_length  (read-u32be port))
	 (padding_length (read-u8    port))
	 (payload        (read-uvector <u8vector>
				       (- packet_length padding_length 1)))
	 (padding        (read-uvector <u8vector> padding_length))
	 )
    (format #t "ssh packet: len=~a, type=~a\n"
	    packet_length
	    (u8vector-ref payload 0))
    payload))

(define (ssh-login)
  (define hostname "localhost")
  (define port 2022)
  (call-with-client-socket
   (make-client-socket 'inet hostname port)
   (lambda (in out)
     (let ((client-version-string "SSH-2.0-femto\r\n")
	   (server-version-string (read-line in)))
       (format out client-version-string)
       (format #t "server version string: ~a\n" server-version-string)

       (ssh-read-packet in))
     )))

(ssh-login)
