;(use femto.dns)
(use binary.io)
(use gauche.collection)
(use gauche.uvector)
(use rfc.base64)

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

(receive (e n)
    (dnskey->rsa-key example-net-dnskey)
  (let* ((str   (base64-decode-string example-net-rrsig-sig))
	 (port  (open-input-string str))
	 (em    (read-uint (string-length str) port 'big-endian))
	 (dec   (expt-mod em e n))
	 (asn1  (call-with-output-string
		  (lambda (port)
		    (write-uint (ceiling->exact (log dec 256))
				dec
				port
				'big-endian)))))
    #?=asn1
    ))


;; ce 26 e9 ce f9 10 0c 7c e1 84 c2 cf 3c 6b 78 5b c6 21 58 4f 60 62 12 6b 4c 2e 08 da 7b a9 5b 90 93 8f 23 75 be 9a 01 fb e8 89 88 42 ad 76 a9 29 c5 63 f4 26 37 4b b1 18 24 9a 73 4b 09 b0 5d a3 keytag => 46809



;; www.example.net. 3600  IN  RRSIG  (A 8 3 3600 20300101000000
;;                     20000101000000 9033 example.net. kRCOH6u7l0QGy9qpC9
;;                     l1sLncJcOKFLJ7GhiUOibu4teYp5VE9RncriShZNz85mwlMgNEa
;;                     cFYK/lPtPiVYP4bwg==);{id = 9033}


(let ((uv (string->u8vector (base64-decode-string dnskey-pubkey))))
  (let* ((elen   (u8vector-ref uv 0))
	 (uv-exp (u8vector 1 (+ 1 elen)))
	 (uv-mod (u8vector (+ 1 elen)))
	 (raw    (u8vector-append (u8vector 1 0 3 8) uv)))
    (format #t "keytag => ~a\n" (calc-keytag raw))))


;;jp.			47880	IN	DS	31714 8 1 B6CB06C153CB0C73BCEBA9914BAF16F26A9B931E
;;jp.			47880	IN	DS	31714 8 2 612693CC16178D788F6A2733E4F01647B027FAE678CB3BF92EC4143F 67A559D8
