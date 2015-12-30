#!/usr/bin/env gosh

(use gauche.net)
(use gauche.uvector)
(use srfi-1)

(add-load-path "/Users/sahara/src/protocols")
(load "./asn1.scm")

(define (asn1-encode-integer i)
  (let1 bytes (let loop ((num i)
			 (l   '()))
		(if (and (> num -127) (< num 128))
		    (cons (mod num 256) l)
		    (receive (q r)
			(div-and-mod num 256)
		      (loop q (cons r l)))))
    (append (list 2 (length bytes)) bytes)))

(define (asn1-encode-octet-string str)
  (if (string? str)
      (asn1-encode-octet-string (string->u8vector str))
      (append (list 4 (u8vector-length str)) (u8vector->list str))))

(define (asn1-encode-null)
  (list 5 0))

(define (asn1-encode-oid . numbers)
  (unless (< (car numbers) 3)
    (error "first octet of OID must be 0, 1 or 2"))
  (cons* 6
	 (- (length numbers) 1)
	 (+ (* (first numbers) 40) (second numbers))
	 (cddr numbers)))

(define (asn1-encode-sequence . objects)
  (let1 joined (apply append objects)
    (cons* (logior #x20 16) (length joined) joined)))

(define (asn1-encode-implicit-sequence . objects)
  (cons #xa0 (cdr (apply asn1-encode-sequence objects))))

(define (main args)
  (let ((sock (make-socket AF_INET SOCK_DGRAM)))
    (socket-connect sock (make <sockaddr-in> :host "127.0.0.1" :port 1616))
    (let1 pkt
	(asn1-encode-sequence
	 (asn1-encode-integer 0)
	 (asn1-encode-octet-string "public")
	 (asn1-encode-implicit-sequence
	  (asn1-encode-integer 1234567890)  ;; request-id
	  (asn1-encode-integer 0)  ;; error-status
	  (asn1-encode-integer 0)  ;; error-index
	  (asn1-encode-sequence
	   (asn1-encode-sequence
	    (asn1-encode-oid 1 3 6 1 2 1 1 1 0)
	    (asn1-encode-null)))))
      (socket-send sock (list->u8vector pkt)))
    ))
;; (main 1)

;; #x30 #0x29  sequence of 41 bytes
;;   #x02 #x01 #x00
;;     integer 0
;;   #x04 #x06 #x70 #x75 #x62 #x6c #x69 #x63
;;     octet-string public
;; #xa0 #x1c  sequence of 30 bytes
;;   #x02 #x04 #x0b #x70 #x7b #x32
;;     integer 191920946
;;   #x02 #x01 #x00
;;     integer 0
;;   #x02 #x01 #x00
;;     integer 0
;;   #x30 #x0e  sequence of 14 bytes
;;     #x30 #x0c  sequence of 12 bytes
;;       #x06 #x08 #x2b #x06 #x01 #x02 #x01 #x01 #x01 #x00
;;         oid 1 3 6 1 2 1 1 1 0
;;       #x05 #x00
;;         null
