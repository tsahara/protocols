#!/usr/bin/env gosh

(use binary.io)
(use binary.pack)
(use gauche.net)
(use gauche.collection)
(use gauche.uvector)
(use gauche.vport)
(use rfc.hmac)
(use rfc.md5)
(use rfc.sha)
(use srfi-1)
(use srfi-19)

;; Utility
(define (get-u24 uv pos)
  (+ (* (get-u8 uv pos) 256 256)
     (* (get-u8 uv (+ pos 1)) 256)
     (get-u8 uv (+ pos 2))))

(define (read-u24 port)
  (read-uint 3 port))

(define (u16->list num)
  (cdr (u24->list num)))

(define (u24->list num)
  (map (cut remainder <> 256)
       (list (quotient num (* 256 256))
	     (quotient num 256)
	     num)))

(define (u32->list num)
  (map (lambda (i)
	 (remainder (quotient num (expt 256 (- 3 i))) 256))
       (iota 4)))

(define (u64->list num)
  (map (lambda (i)
	 (remainder (quotient num (expt 256 (- 7 i))) 256))
       (iota 8)))

(define (u8vector-join . uv-list)
  (let ((uvec (make-u8vector (apply + (map u8vector-length uv-list)))))
    (let loop ((i   0)
	       (uvl uv-list))
      (if (null? uvl)
	  uvec
	  (begin
	    (u8vector-copy! uvec i (car uvl))
	    (loop (+ i (u8vector-length (car uvl))) (cdr uvl)))))))

(define (hexdump uv)
  (let1 len (u8vector-length uv)
    (let show-a-line ((base 0))
      (if (< base len)
	  (begin
	    (format #t "~8,'0x" base)
	    (dotimes (i (min 16 (- len base)))
	      (format #t " ~a~2,'0x"
		      (if (= (remainder i 8) 0) " " "")
		      (u8vector-ref uv (+ base i))))
	    (if (< len (+ base 16))
		(dotimes (i (- (+ base 16) len))
		  (display "   ")))
	    (display "  |")
	    (dotimes (i (min 16 (- len base)))
	      (let1 ch (integer->char (u8vector-ref uv (+ base i)))
		(display (if (char-set-contains? #[[:print:]] ch)
			     ch
			     #\.))))
	    (display "|")
	    (newline)
	    (show-a-line (+ base 16))
	    )))))

(define *content-type-change_cipher_spec* 20)
(define *content-type-alert*              21)
(define *content-type-handshake*          22)
(define *content-type-application-data*   23)

(define *ciphersuite-list*
  '((#x00 #x01 "TLS_RSA_WITH_NULL_MD5")
    (#x00 #x05 "TLS_RSA_WITH_RC4_128_SHA")))

(define (insecure-random-sequence byte-count)
  (iota byte-count))

(define *client-random* #f)


(define-class <tls-session> ()
  ((socket                :init-value #f)
   (read-sequence-number  :init-value 0)
   (client-sequence-number :init-value 0)
   (do-encrypt            :init-value #f)
   (premaster-secret      :init-value #f)
   (master-secret         :init-value #f)
   (client-hello-random   :init-value #f)
   (server-hello-random   :init-value #f)
   (client-write-mac-secret :init-value #f)
   (server-write-mac-secret :init-value #f)
   (handshake-md5         :init-form (make <md5>))
   (handshake-sha1        :init-form (make <sha1>))
   ))

(define (make-tls socket)
  (let1 tls (make <tls-session>)
    (slot-set! tls 'socket socket)
    tls))

;; make keys from premaster secret
(define (tls-calculate-keys tls)
  (slot-set! tls 'master-secret
	     (tls-prf (slot-ref tls 'premaster-secret)
		      "master secret"
		      (u8vector-join (slot-ref tls 'client-hello-random)
				     (slot-ref tls 'server-hello-random))
		      48))
  (let1 keys (tls-prf (slot-ref tls 'master-secret)
		      "key expansion"
		      (u8vector-join (slot-ref tls 'server-hello-random)
				     (slot-ref tls 'client-hello-random))
		      (+ 16 16 0 0 0 0))
    (slot-set! tls 'client-write-mac-secret (u8vector-copy keys  0 16))
    (slot-set! tls 'server-write-mac-secret (u8vector-copy keys 16 32))
    ;; XXX

    (slot-set! tls 'do-encrypt #t)
    ))

(define (tls-client-sequence-number tls)
  (let1 seq (slot-ref tls 'client-sequence-number)
    (slot-set! tls 'client-sequence-number (+ 1 seq))
    seq))

(define (tls-make-client-random tls)
  (slot-set! tls 'client-hello-random
	     (list->u8vector
	      (append (u32->list (time-second (current-time)))
		      (insecure-random-sequence 28)))))

(define (tls-make-premaster-secret tls major minor)   ; => u8vector
  (slot-set! tls 'premaster-secret
	     (list->u8vector
	      (append (list 3 1) (insecure-random-sequence 46)))))

(define (tls-client-hello tls)
  (tls-make-client-random tls)
  (list->u8vector
   (make-tls-handshake tls 1
		       (append (list 3 1)          ; client_version
			       (u8vector->list
				(slot-ref tls 'client-hello-random))
			       (list 0)            ; SessionID length
			       (list 0 4 0 0 0 1)  ; cipher_suites
					           ; TLS_RSA_WITH_NULL_MD5
			       (list 1 0)          ; compression_methods 0
			       ))))


(define (p-hash hash hashlen secret seed len)
  (let loop ((output (make-u8vector len))
	     (a0     seed)
	     (index  0))
    (if (< (* index hashlen) len)
	(let* ((a (hmac-digest-string a0 :key secret :hasher hash))
	       (h (hmac-digest-string (string-append a seed)
				      :key secret :hasher hash)))
	  (u8vector-copy! output (* index hashlen) (string->u8vector h))
	  (loop output a (+ index 1)))
	(u8vector-copy output 0 len))))

(define (tls-prf secret label seed len) ; => uvec
  (let ((md5-secret  (u8vector->string
		      (u8vector-copy secret 0
				     (ceiling (/ (u8vector-length secret) 2)))))
	(sha1-secret (u8vector->string
		      (u8vector-copy secret
				     (floor (/ (u8vector-length secret) 2)))))
	(labelseed   (string-append label (u8vector->string seed))))
    (u8vector-xor (p-hash <md5>  16 md5-secret  labelseed len)
		  (p-hash <sha1> 20 sha1-secret labelseed len))))

;; ClientKeyExchange => EncryptedPreMasterSecret
;;  EncryptedPreMasterSecret =>
(define (rsa-encrypt uvec e n)

  ;; EB = 00 || BT || PS || 00 || D
  (let* ((k  (ceiling->exact (log n 256)))  ; length of modulus in octets
	 (eb (append (list 0 2)
		     (iota (- k 3 (u8vector-length uvec)) 2)
		     (list 0)
		     (u8vector->list uvec)))
	 (x  (fold (lambda (n prev) (+ (* 256 prev) n)) 0 eb))
	 (y  (expt-mod x e n)))
    (list->u8vector
     (map (lambda (i)
	    (modulo
	     (quotient y (expt 256 (- k i 1)))
	     256))
	  (iota k)))))

(define (make-tls-plaintext tls type payload)
  (append (list type 3 1)
	  (u16->list (length payload))
	  payload))

(define (make-tls-ciphertext tls type payload)
  (define (make-mac)
    (u8vector->list
     (string->u8vector
      (hmac-digest-string (u8vector->string
			   (apply u8vector
				  (append (u64->list
					   (tls-client-sequence-number tls))
					  (make-tls-plaintext tls type payload))))
			  :key (u8vector->string
				(slot-ref tls 'client-write-mac-secret))
			  :hasher <md5>))))

  (let ((mac (make-mac)))
    (append (list type 3 1)
	    (u16->list (+ (length payload) (length mac)))
	    payload
	    mac)))  ;; GenericStreamCipher

(define (make-tls-record tls type body)
  ((if (slot-ref tls 'do-encrypt)
       make-tls-ciphertext
       make-tls-plaintext)
   tls type body))

(define (make-tls-handshake tls type body)
  (let* ((handshake-list (append (list type)
				 (u24->list (length body))
				 body))
	 (handshake-uv   (apply u8vector handshake-list)))
    (digest-update! (slot-ref tls 'handshake-md5)  handshake-uv)
    (digest-update! (slot-ref tls 'handshake-sha1) handshake-uv)
    (while #f
      (print "Update handshake-<md>:")
      (hexdump handshake-uv))
    (make-tls-record tls 22 handshake-list)))

(define (tls-client-key-exchange tls e n)
  (tls-make-premaster-secret tls 3 1)
  (print "premaster-secret")
  (hexdump (slot-ref tls 'premaster-secret))
  (let1 encrypted (rsa-encrypt (slot-ref tls 'premaster-secret)
			       e n)
    (make-tls-handshake tls
			16
			(append (u16->list (u8vector-length encrypted))
				(u8vector->list encrypted)))))

(define (tls-finished tls)
  (let ((md5-digest  (digest-final! (slot-ref tls 'handshake-md5)))
	(sha1-digest (digest-final! (slot-ref tls 'handshake-sha1))))
    (print "md5")
    (hexdump (string->u8vector md5-digest))

    (print "sha1")
    (hexdump (string->u8vector sha1-digest))

    (make-tls-handshake tls 20
			(u8vector->list
			 (tls-prf (slot-ref tls 'master-secret)
				  "client finished"
				  (string->u8vector
				   (string-append md5-digest sha1-digest))
				  12)))))

(define (tls-change-cipher-spec tls)
  (make-tls-plaintext tls 20 (list 1)))

(define (send-client-hello sock tls)
  (format #t "send TLS Client Hello\n")
  (socket-send sock (tls-client-hello tls)))

(define (send-tls-key-exchange sock tls e n)
  (format #t "send TLS Key Exchange: e=~a n=~a\n" e n)
  (socket-send sock (list->u8vector (tls-client-key-exchange tls e n))))

(define (send-change-cipher-spec sock tls)
  (socket-send sock (list->u8vector (tls-change-cipher-spec tls))))

(define (send-finished sock tls)
  (let ((d (list->u8vector (tls-finished tls))))
    (print "client finished")
    (hexdump d)
    (socket-send sock d)))

(define (tls-send-application-data tls uvec)
  (socket-send (slot-ref tls 'socket)
	       (list->u8vector
		(make-tls-ciphertext tls 23 (u8vector->list uvec)))))

;; enum {
;;     hello_request(0), client_hello(1), server_hello(2),
;;     certificate(11), server_key_exchange (12),
;;     certificate_request(13), server_hello_done(14),
;;     certificate_verify(15), client_key_exchange(16),
;;     finished(20), (255)
;; } HandshakeType;

;; struct {
;;     uint32 gmt_unix_time;
;;     opaque random_bytes[28];
;; } Random;

;; opaque SessionID<0..32>;

;; struct {
;;         ProtocolVersion server_version;
;;         Random random;
;;         SessionID session_id;
;;         CipherSuite cipher_suite;
;;         CompressionMethod compression_method;
;;         select (extensions_present) {
;;             case false:
;;                 struct {};
;;             case true:
;;                 Extension extensions<0..2^16-1>;
;;         };
;;     } ServerHello;

(define (tls-read-protocol-version port)
  (let* ((a (read-u8 port))
	 (b (read-u8 port)))
    (cons a b)))

(define (tls-read-session-id port)
  (let1 len (read-u8 port)
    (read-uvector <u8vector> len port)))

(define (tls-read-ciphersuite port)
  (let* ((a (read-u8 port))
	 (b (read-u8 port)))
    (cons a b)))

(define (read-record port tls)
  (let ((type           (read-u8 port))
	(protocol-major (read-u8 port))
	(protocol-minor (read-u8 port))
	(len            (read-u16 port)))
    (format #t "TLS record: type=~a version=~a.~a length=~a\n"
	    (tls-record-type->string type)
	    protocol-major
	    protocol-minor
	    len
	    )
    (case type
      ((20) ;; Change Cipher Spec
       (let ((type (read-u8 port)))
	 (if (not (= type 1))
	     (errorf "TLS Error: ChangeCipherSpec received but type is ~a (!= 1)" type))
	 ))

      ((21) ;; Alert
       (let* ((level (read-u8 port))
	      (desc  (read-u8 port)))
	 (format #t "TLS Alert: level=~a desc=~a\n" level desc)))

      ((22) ;; Handshake
       (begin
	 (let* ((record    (read-uvector <u8vector> len port))
		(port      (open-input-string (u8vector->string record)))
		(hs-type   (read-u8 port))
		(hs-length (read-u24 port)))
	   (format #t "TLS Handshake type=~a length=~a\n"
		   (tls-handshake-type->string hs-type)
		   hs-length)

	   (digest-update! (slot-ref tls 'handshake-md5)  record)
	   (digest-update! (slot-ref tls 'handshake-sha1) record)

	   (case hs-type
	     ;; Server Hello
	     ((2) (begin
		    (let* ((server-version (tls-read-protocol-version port))
			   (server-random  (read-uvector <u8vector> 32 port))
			   (session-id         (tls-read-session-id port))
			   (ciphersuite        (tls-read-ciphersuite port))
			   (compression-method (read-u8 port))
			   )
		      (slot-set! tls 'server-hello-random server-random)
		      (format #t "TLS Server Hello version=~a session-id=(~a) cipher=0x~x,0x~x\n"
			      (tls-protocol-version->string server-version)
			      (u8vector-length session-id)
			      (car ciphersuite) (cdr ciphersuite)))))
	     ;; Certificate
	     ((11) (begin
		     (let ((cert-list-length (read-u24 port)))
		       (format #t "Certificate length=~a\n" cert-list-length)
		       (let* ((cert-length (read-u24 port))
			      (cert-uvec (read-uvector <u8vector>
						       cert-length
						       port))
			      (cert (decode-x509-der cert-uvec)))
			 (let* ((subject-public-key-info
				 (seventh (car cert)))
				(pubkey-bits (cadr subject-public-key-info))
				(pubkey (decode-x509-der (third pubkey-bits))))
			   (values (third (second pubkey))
				   (third (first  pubkey))))
			 ))))
	     ))))

      ((23) ;; Application Data
       (print (u8vector->string
	       (read-uvector <u8vector> len port))))

      (else (errorf "unknown Record Type=~a" type)))))

(define (decode-x509-der uvec)

  ;; u8vector -> (values byte-length (tag class flag value))
  (define (decode-asn1 uvec offset)
    (receive (tag-len class flag tag)
	(decode-tag uvec offset)
      (receive (len-len value-len)
	  (decode-length uvec (+ offset tag-len))
	(values
	 (+ tag-len len-len value-len)
	 (decode-value uvec (+ offset tag-len len-len) value-len tag class)))))

  (define (decode-tag uvec offset)
    (let1 byte (u8vector-ref uvec offset)
      (let ((class (bit-field byte 6 8))
	    (flag  (bit-field byte 5 6))
	    (num   (bit-field byte 0 5)))
	(if (= num 3) (format #t "bit-string: flag=~a\n" flag))
	(case class
	  ((0) ;; Universal
	   (values 1 class flag
		   (case num
		     ;; tag numbers
		     ((1)  'boolean)
		     ((2)  'integer)
		     ((3)  'bit-string)
		     ((4)  'octet-string)
		     ((5)  'null)
		     ((6)  'oid)
		     ((16) 'sequence)
		     ((17) 'set)
		     ((19) 'printable-string)
		     ((23) 'utc-time)
		     (else => (cut errorf "ASN.1: tag number is ~a" <>))
		     )))
	  ((1) ;; Application
	   (error "ASN.1: class is application(!?)"))
	  ((2) ;; Context-specific
	   (values 1 class flag num))
	  ((3) ;; Private
	   (error "ASN.1: class is private(!?)"))))))

  (define (decode-length uvec offset)
    (let1 len0 (u8vector-ref uvec offset)
      (if (< len0 128)
	  ;; short form
	  (values 1 len0)
	  ;; long form
	  (let1 len-of-len (bit-field len0 0 7)
	    (values (+ 1 len-of-len)
		    (read-uint len-of-len
			       (open-input-uvector
				(u8vector-copy uvec
					       (+ offset 1)
					       (+ offset 1 len-of-len)))
			       'big-endian
			       ))))))

  (define (decode-value uvec offset len tag class)
    (if (= class 2)
	(receive (v n)
	    (decode-asn1 uvec offset)
	  (values (list tag `((tag . ,tag)) v) len))
	(case tag
	  ;; Integer
	  ((integer)
	   (format #t "uvec=(~a) offset=~a len=~a\n"
		   (u8vector-length uvec) offset len)
	   (list tag class
		 (read-sint len
			    (open-input-string
			     (u8vector->string
			      (u8vector-copy uvec offset (+ offset len)))))))

	  ;; BIT STRING
	  ((bit-string)
	   (list tag class (decode-bit-string
			    (u8vector-copy uvec offset (+ offset len)))))

	  ;; OCTET STRING => #u8(3 1 4)
	  ((octet-string)
	   (list tag class (u8vector-copy uvec offset (+ offset len))))

	  ;; NULL => '()
	  ((null)
	   (list tag class '()))

	  ;; OBJECT IDENTIFIER => (list 1 2 840 113549)
	  ((oid)
	   (list tag class
		 (decode-oid (u8vector-copy uvec offset (+ offset len)))))

	  ;; SET => (list a b c)
	  ((sequence set)
	   (let loop ((offs offset)
		      (rl   (list)))
	     (if (< offs (+ offset len))
		 (begin
		   ;;(format #t "seq[~a]: rl=~a\n" (length rl) rl)
		   (receive (n val)
		       (decode-asn1 uvec offs)
		     (loop (+ offs n)
			   (cons val rl))))
		 (values (reverse rl) (- offs offset)))))

	  ;; Printable String
	  ((printable-string)
	   (list tag (u8vector->string uvec offset (+ offset len))))

	  ;; UTCTime => <date>
	  ((utc-time)
	   (decode-utc-time (u8vector-copy uvec offset (+ offset len))))

	  (else => (cut errorf "unsupported tag: ~a" <>)))))

  (receive (len asn1-object)
      (decode-asn1 uvec 0)
    asn1-object))

(define (decode-oid uvec)
  (receive (1st 2nd)
      (quotient&remainder (u8vector-ref uvec 0) 40)
    (let loop ((rl   (list 2nd 1st))
	       (offs 1)
	       (num  0))
      (if (< offs (u8vector-length uvec))
	  (let1 val (u8vector-ref uvec offs)
	    (if (< val 128)
		(loop (cons (+ num val) rl)
		      (+ offs 1)
		      0)
		(loop rl
		      (+ offs 1)
		      (* 128 (+ num (- val 128))))))
	  (reverse rl)))))

(define (decode-utc-time uvec)
  (rxmatch-let (#/^(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)?(Z|[-+]\d\d\d\d)$/
		   (u8vector->string uvec))
      (#f year month day hour minute second timezone)
    (make-date 0
	       (string->number second)
	       (string->number minute)
	       (string->number hour)
	       (string->number day)
	       (string->number month)
	       (let1 y (string->number year)
		 (+ y (if (< y 50) 2000 1900)))
	       0)))

(define (decode-bit-string uvec)
  (let1 unused (u8vector-ref uvec 0)
    ;; XXX
    (u8vector-copy uvec 1 (u8vector-length uvec))))

(define (tls-protocol-version->string ver)
  (cond ((equal? ver '(3 . 1)) "TLS1.0")
	((equal? ver '(3 . 2)) "TLS1.1")
	((equal? ver '(3 . 3)) "TLS1.2")
	(else (format #f "unknown_version_~d_~d" (car ver) (cdr ver)))))

(define (tls-record-type->string type)
  (case type
    ((20) "change_cipher_spec")
    ((21) "alert")
    ((22) "handshake")
    ((23) "application_data")
    (else (format #f "unknown_record_type(~a)" type))))

(define (tls-handshake-type->string type)
  (case type
    ((0)  "hello_request")
    ((1)  "client_hello")
    ((2)  "server_hello")
    ((11) "certificate")
    ((12) "server_key_exchange")
    ((13) "certificate_request")
    ((14) "server_hello_done")
    ((15) "certificate_verify")
    ((16) "client_key_exchange")
    ((20) "finished")
    (else (format #f "unknown_handshake_type(~a)" type))))

(if #f
    (let1 cert (string->u8vector (port->string
				  (open-input-file "/Users/sahara/src/protocols/tls/ca.der")))
      (let* ((subject-public-key-info (seventh (car (decode-x509-der cert))))
	     (pubkey (cadr subject-public-key-info)))
	(hexdump (caddr pubkey))
	(decode-x509-der (caddr pubkey))
	))
    )

(define (main args)
  (default-endian 'big-endian)
  (let* ((sock (make-client-socket 'inet "localhost" 4433))
	 (tls  (make-tls sock)))
    (send-client-hello sock tls)
    (read-record (socket-input-port sock) tls)
    (receive (e n)
	(read-record (socket-input-port sock) tls)
      (read-record (socket-input-port sock) tls)
      (send-tls-key-exchange sock tls e n)
      (send-change-cipher-spec sock tls)
      (tls-calculate-keys tls)
      (send-finished sock tls)
      (read-record (socket-input-port sock) tls) ;; ChangeCipherSpec

      (tls-send-application-data tls (string->u8vector "GET / HTTP/1.0\r\n\r\n"))

      (while #t
	(read-record (socket-input-port sock) tls))

      (socket-close sock)
      )))
