(use binary.io)
(use binary.pack)
(use gauche.collection)
(use gauche.uvector)
(use rfc.base64)
(use rfc.sha)
(use srfi-13)
(use srfi-19)
(use sxml.ssax)

#;(define (load-trust-anchor)
  (let1 sxml (ssax:xml->sxml (open-input-file "root-anchors.xml") '())
    ))
;(print (load-trust-anchor))

(define (calc-keytag uv)
  (let ((len (u8vector-length uv))
	(sum 0))
    (dotimes (i (quotient len 2))
      (set! sum (+ sum
		   (* 256 (u8vector-ref uv (* i 2)))
		   (u8vector-ref uv (+ (* i 2) 1)))))
    (if (= (remainder len 2) 1)
	(set! sum (+ sum (* 256 (u8vector-ref uv (- len 1))))))
    (remainder (+ (quotient sum #x10000)
		  sum)
	       #x10000)))

;; .			77174	IN	DNSKEY	256 3 8 AwEAAcRIZfxskdElMKgjwvWQO2bQe7EGAvX6zgIaqmbsaMqmMrIpd1+b P7nyULLuL8jWnKAqcaVfal2yJD50gg5zFl5yW/F9dKNXXEFI7VEcGrPy G6/OrA9RBU8pGWm0qxpsNm5UIgTU5IX7pb/0rBj67c/R7qln8sjH1yls r4f1Y3R6p/druiEalKasEjGKA9L2w9jzUQusWxM7fQx/T8c/3x3bsjve D1dleQ6MJaCx4bpPXYZpqXmSvGn+T2v5350cBVAFqVKhGbjxEyXAweem 8cTU4L1p+DV7Ua11a1tMf0Tlu8pkpLwh7NQIggIEhJwEhPeXE3E4C6Q2 /PFENcoFERc=

(define dnskey-pubkey "AwEAAcRIZfxskdElMKgjwvWQO2bQe7EGAvX6zgIaqmbsaMqmMrIpd1+b P7nyULLuL8jWnKAqcaVfal2yJD50gg5zFl5yW/F9dKNXXEFI7VEcGrPy G6/OrA9RBU8pGWm0qxpsNm5UIgTU5IX7pb/0rBj67c/R7qln8sjH1yls r4f1Y3R6p/druiEalKasEjGKA9L2w9jzUQusWxM7fQx/T8c/3x3bsjve D1dleQ6MJaCx4bpPXYZpqXmSvGn+T2v5350cBVAFqVKhGbjxEyXAweem 8cTU4L1p+DV7Ua11a1tMf0Tlu8pkpLwh7NQIggIEhJwEhPeXE3E4C6Q2 /PFENcoFERc=")

(let ((uv (string->u8vector (base64-decode-string dnskey-pubkey))))
  (let* ((elen   (u8vector-ref uv 0))
	 (uv-exp (u8vector 1 (+ 1 elen)))
	 (uv-mod (u8vector (+ 1 elen)))
	 (raw    (u8vector-append (u8vector 1 0 3 8) uv)))
    (format #t "keytag => ~a\n" (calc-keytag raw))))

;; jp.			86400	IN	RRSIG	DS
;; alg=8=RSASHA256 1 86400 expire=20171119210000 inception=20171106200000
;; keytag=46809
;; signer=.
;; ZYHOOzZo7aejB5ObtL7sB8h1+JXZ+68S7LJsirEW9IfYiJepMrXKfEFw 0dTb9mT3e0tWUMmjfgX6Bf462NfCPpmPrzPcXofb3nd/ZLFsFNp9nK7R BY3itYTAf0XyQxuA2c3UAfA3tgjnLEitEF25UdSQreA88cyChrNweSs2 sdZMThUeQ8gMLjYYgPXKn8jChVIhUL3t9kzTtOuSb/hiMzpYM6uVrcFw tr+jFr184GyDGMpzC5TKDaA/LVlvcZ2X3MJ5+6ty5i6znXkPeiTondl6 HSqEbS7rthKgOKH3EC7P0rG/dMK6Ted4CqPBv/ar8nwdv+kv75hVEm2e gnAURw==

;; RFC5702 6.1
(define example-net-dnskey "AwEAAcFcGsaxxdgiuuGmCkVI my4h99CqT7jwY3pexPGcnUFtR2Fh36BponcwtkZ4cAgtvd4Qs8P kxUdp6p/DlUmObdk=")

(define example-net-rrsig-sig "kRCOH6u7l0QGy9qpC9 l1sLncJcOKFLJ7GhiUOibu4teYp5VE9RncriShZNz85mwlMgNEa cFYK/lPtPiVYP4bwg==")

(define (dnskey->rsa-key str)
  (let ((port (open-input-string (base64-decode-string str))))
    (let1 byte0 (read-u8 port)
      (let1 exp-len (if (= byte0 0)
			(+ (* 256 (read-u8 port))
			   (read-u8 port))
			byte0)
	(format #t "exp len = ~a\n" exp-len)
	(let* ((exp (read-uint exp-len port 'big-endian))
	       (modulo (read-uint (string-length
				   (get-remaining-input-string port))
				  port
				  'big-endian)))
	  (format #t "exp=~a, modulo=~a\n" exp modulo)
	  (values exp modulo))))))

(define (parse-encrypted-block asn1)
  (let1 block-type (u8vector-ref asn1 0)
    (let loop ((i 1))
      (if (= (u8vector-ref asn1 i) #xff)
	  (loop (+ i 1))
	  (begin
	    (unless (= (u8vector-ref asn1 i) 0)
	      (error "paddings must be followed by 0"))
	    (u8vector-copy asn1 (+ i 1)))))))

(define (u8vector-compare uv1 uv2 len)
  (let loop ((i 0))
    (if (= i len)
	#t
	(if (eq? (u8vector-ref uv1 i) (u8vector-ref uv2 i))
	    (loop (+ i 1))
	    #f))))

(define sha256-prefix (u8vector #x30 #x31 #x30 #x0d #x06 #x09 #x60
				#x86 #x48 #x01 #x65 #x03 #x04 #x02
				#x01 #x05 #x00 #x04 #x20))

(define sha512-prefix (u8vector #x30 #x51 #x30 #x0d #x06 #x09 #x60
				#x86 #x48 #x01 #x65 #x03 #x04 #x02
				#x03 #x05 #x00 #x04 #x40))

;; www.example.net. 3600  IN  RRSIG  (A 8 3 3600 20300101000000
;;                     20000101000000 9033 example.net. kRCOH6u7l0QGy9qpC9
;;                     l1sLncJcOKFLJ7GhiUOibu4teYp5VE9RncriShZNz85mwlMgNEa
;;                     cFYK/lPtPiVYP4bwg==);{id = 9033}

(define (dns-encode-name str)
  (define (string-last-char str)
    (string-ref str (- (string-length str) 1)))
  (if (string=? "." str)
      "\0"
      (apply u8vector-append
	     (map (lambda (label)
		    (u8vector-append (u8vector (string-length label))
				     (string->u8vector label)))
		  (string-split (if (eq? #\. (string-last-char str))
				    str
				    (string-append str "."))
				#\.)))))

(define (validate-rrsig)
  (define (make-hash-from-data signer)
    (define (make-unixtime str)
      (time->seconds
       (date->time-utc
	(string->date (string-append str "+0000")
		      "~Y~m~d~H~M~S~z"))))

    (define (make-rrsig-rdata)
      (u8vector-append (string->u8vector
			(pack "nCCNNNn" `(1
					  8
					  3
					  3600
					  ,(make-unixtime "20300101000000")
					  ,(make-unixtime "20000101000000")
					  9033)
			      :to-string? #t))
		       (dns-encode-name signer)))

    ;; www.example.net. 3600  IN  A  192.0.2.91
    (define (make-rr)
      (u8vector-append (dns-encode-name "www.example.net")
		       (string->u8vector
			(pack "nnNn" `(1
				       1
				       3600
				       4)
			      :to-string? #t))
		       (u8vector 192 0 2 91)))

    (string->u8vector
     (sha256-digest-string
      (u8vector->string
       (u8vector-append (make-rrsig-rdata)
			(make-rr))))))

  (receive (e n)
      (dnskey->rsa-key example-net-dnskey)
    (let* ((str   (base64-decode-string example-net-rrsig-sig))
	   (port  (open-input-string str))
	   (em    (read-uint (string-length str) port 'big-endian))
	   (dec   (expt-mod em e n))
	   (encrypted-block (string->u8vector
			     (call-with-output-string
			       (lambda (port)
				 (write-uint (ceiling->exact (log dec 256))
					     dec
					     port
					     'big-endian)))))
	   (data  (parse-encrypted-block encrypted-block))
	   (hash  (u8vector-copy data 19)))

      (unless (u8vector-compare data sha256-prefix 19)
	(error "unknown prefix"))

      (format #t "hash from rrsig: ~a\n" hash)
      (format #t "hash from data:  ~a\n"
	      (make-hash-from-data "example.net"))
      )))
(validate-rrsig)

;; ce 26 e9 ce f9 10 0c 7c e1 84 c2 cf 3c 6b 78 5b c6 21 58 4f 60 62 12 6b 4c 2e 08 da 7b a9 5b 90 93 8f 23 75 be 9a 01 fb e8 89 88 42 ad 76 a9 29 c5 63 f4 26 37 4b b1 18 24 9a 73 4b 09 b0 5d a3 keytag => 46809

(define (dnskey-pubkey->keytag dnskey-rdata)
  (let ((uv (string->u8vector (base64-decode-string dnskey-rdata))))
    (let* ((elen   (u8vector-ref uv 0))
	   (uv-exp (u8vector 1 (+ 1 elen)))
	   (uv-mod (u8vector (+ 1 elen)))
	   (raw    (u8vector-append (u8vector 1 0 3 8) uv)))
      (calc-keytag raw))))

(format #t "keytag => ~a\n" (dnskey-pubkey->keytag dnskey-pubkey))

;;
;; Parse Trust Anchor
;;

(define trust-anchor-1 '(19036 . "49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5"))

(define trust-anchor-2 '(20326 . "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"))

(define root-dnskey-2 "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3 +/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kv ArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF 0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+e oZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfd RUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwN R1AkUTV74bU=")

(let1 digest-from-dnskey
    (let1 rdata (string-append (pack "nCC" `(257 3 8) :to-string? #t)
			       (base64-decode-string root-dnskey-2))
      (string-upcase
       (digest-hexify
	(sha256-digest-string
	 (string-append (make-byte-string 1 0)
			rdata)))))
  (format #t "from DNSKEY => ~a\n" digest-from-dnskey)
  (format #t "trust anchor > ~a\n" (cdr trust-anchor-2))
  )

#?=(dns-encode-name ".")

;;jp.			47880	IN	DS	31714 8 1 B6CB06C153CB0C73BCEBA9914BAF16F26A9B931E
;;jp.			47880	IN	DS	31714 8 2 612693CC16178D788F6A2733E4F01647B027FAE678CB3BF92EC4143F 67A559D8
