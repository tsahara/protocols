(define-module femto.dns
  (use binary.io)
  (use femto.pktbuf)
  (use gauche.collection)
  (use gauche.net)
  (use gauche.uvector)
  (use srfi-13)
  (use srfi-19)
  (export show-dns-packet
          make-dns-query
          parse-dns-packet
          dns-packet-question-rr
          dns-class-in
          dns-class-any
          dns-read-resolv-conf
          dns-type-a
          dns-type-ns
          dns-type-cname
          dns-type-soa
          dns-type-mx
          dns-type-txt
          dns-type-aaaa
          dns-type-rrsig
          dns-type-axfr
          dns-type-any
	  dns-server
          ))
(select-module femto.dns)

(define *dns-server* #f)

(define dns-class-in 1)
(define dns-class-any 255)

(define dns-type-a	1)
(define dns-type-ns	2)
(define dns-type-cname	5)
(define dns-type-soa    6)
(define dns-type-mx	15)
(define dns-type-txt	16)
(define dns-type-aaaa   28)
(define dns-type-rrsig  49)
(define dns-type-axfr	252)
(define dns-type-any	255)

(define-class <dns-rr> ()
  ((name) (class) (type)))

(define-method dns-rr-name ((rr <dns-rr>))
  (ref rr 'name))

;; return one of dns-class-XXXX
(define-method dns-rr-class ((rr <dns-rr>))
  (ref rr 'class))

;; return one of dns-type-XXXX
(define-method dns-rr-type ((rr <dns-rr>))
  (ref rr 'type))

(define-method write-object ((rr <dns-rr>) out)
  (format out "#<dns-rr virtual-class>"))


(define-class <dns-packet> ()
  ((bytes)))

(define-method write-object ((dnsp <dns-packet>) out)
  (format out "#<dns-packet>"))

(define (parse-dns-packet vec len)
  (let ((dnsp (make <dns-packet>))
        (buf (u8vector-copy vec 0 len))
        (qdcount (get-u16be vec 4))
        (ancount (get-u16be vec 6))
        (nscount (get-u16be vec 8))
        (arcount (get-u16be vec 10))
        (ptr 12))
    (vector-set! dnsp 2 (make-vector qdcount))
    (vector-set! dnsp 3 (make-vector ancount))
    (vector-set! dnsp 4 (make-vector nscount))
    (vector-set! dnsp 5 (make-vector arcount))
    (let qdloop ((i 0))
      (if (< i qdcount)
          (receive (qname qtype qclass len)
              (parse-question-section buf ptr)
            (vector-set! (vector-ref dnsp 2) i ptr)
            (set! ptr (+ ptr len))
            (qdloop (+ i 1)))))
    (let anloop ((i 0))
      (if (< i ancount)
          (receive (name namelen)
              (get-name buf ptr)
            (vector-set! (vector-ref dnsp 3) i ptr)
            (set! ptr (+ ptr namelen 10
                         (get-u16be buf (+ ptr namelen 8))))  ; RDLENGTH
            (anloop (+ i 1)))))
    (let nsloop ((i 0))
      (if (< i nscount)
          (receive (name namelen)
              (get-name buf ptr)
            (vector-set! (vector-ref dnsp 4) i ptr)
            (set! ptr (+ ptr namelen 10
                         (get-u16be buf (+ ptr namelen 8))))  ; RDLENGTH
            (nsloop (+ i 1)))))
    (let arloop ((i 0))
      (if (< i arcount)
          (receive (name namelen)
              (get-name buf ptr)
            (vector-set! (vector-ref dnsp 5) i ptr)
            (set! ptr (+ ptr namelen 10
                         (get-u16be buf (+ ptr namelen 8))))  ; RDLENGTH
            (arloop (+ i 1)))))
    dnsp))



(define (make-qname name)
  (let ((buf (make-pktbuf)))
    (for-each (lambda (label)
                (for-each (lambda (c)
                            (pktbuf-append-byte buf c))
                          (cons (string-length label)
                                (map char->integer (string->list label)))))
              (string-split name #\.))
    (pktbuf-append-byte buf 0)
    (pktbuf->u8vector buf)))

(define (make-dns-query domain type)
  (let ((header (make-u8vector 12))
	(qsec   (make-pktbuf (make-qname domain))))
    (put-u16be! header 0 1)		; transaction ID
    (put-u16be! header 2 #x0100)	; flags
    (put-u16be! header 4 1)		; QDCOUNT
    (put-u16be! header 6 0)		; ANCOUNT
    (put-u16be! header 8 0)		; NSCOUNT
    (put-u16be! header 10 0)		; ARCOUNT

    (pktbuf-append-u16 qsec type)
    (pktbuf-append-u16 qsec dns-class-in)

    (list->u8vector (append (u8vector->list header)
			    (u8vector->list (pktbuf->u8vector qsec))))
    ))

(define (make-dns-packet0)
  (make-dns-query "www.kame.net" dns-type-a))

(define (make-dns-packet)
  (make-dns-query "www.kame.net" dns-type-aaaa))

(define (get-name vec offset)
  (define (label->string vec offset len)
    (apply string
	   (map integer->char (u8vector->list vec offset (+ offset len)))))
  (define (read-pointer pos)
    (label->string vec (+ 1 pos) (get-u8 vec pos)))
  (let loop ((labels '())
	     (pos offset))
    (let ((len (get-u8 vec pos)))
      (cond ((= len 0)
	     (values (string-join labels ".")
		     (- (+ pos 1) offset)))
	    ((< len 64)
	     (loop (append! labels (list (label->string vec (+ 1 pos) len)))
		   (+ pos 1 len)))
	    ((>= len 192)
	     (receive (pname plen)
		 (get-name vec (logand (get-u16be vec pos) #x3fff))
	       (values (string-join (append labels (list pname)) ".")
		       (- (+ pos 2) offset))))
	    (else (error "label too long ~a\n" len))))))

;; returns (name type class length-of-question-section)
(define (parse-question-section vec pos)
  (receive (name len)
      (get-name vec pos)
    (values name
	    (get-u16be vec (+ pos len))
	    (get-u16be vec (+ pos len 2))
	    (+ len 4))))

(define (dns-packet-buffer dnsp)
  (vector-ref dnsp 0))

(define (dns-packet-question-count dnsp)
  (parse-question-section (vector-ref dnsp 2) 0))

(define (dns-packet-question-rr dnsp)
  (receive (name type class n)
      (parse-question-section dnsp 0)
    (values name type class)))

(define (dns-packet-answer-count dnsp)
  (vector-length (vector-ref dnsp 3)))

(define (dns-packet-authority-count dnsp)
  (vector-length (vector-ref dnsp 4)))

(define (dns-packet-additional-count dnsp)
  (vector-length (vector-ref dnsp 5)))


(define (parse-dns-packet0 vec len)
  (let ((dnsp (make-vector 6))
        (buf (u8vector-copy vec 0 len))
        (qdcount (get-u16be vec 4))
        (ancount (get-u16be vec 6))
        (nscount (get-u16be vec 8))
        (arcount (get-u16be vec 10))
        (ptr 12))
    (vector-set! dnsp 0 buf)
    (vector-set! dnsp 2 (make-vector qdcount))
    (vector-set! dnsp 3 (make-vector ancount))
    (vector-set! dnsp 4 (make-vector nscount))
    (vector-set! dnsp 5 (make-vector arcount))
    (let qdloop ((i 0))
      (if (< i qdcount)
          (receive (qname qtype qclass len)
              (parse-question-section buf ptr)
            (vector-set! (vector-ref dnsp 2) i ptr)
            (set! ptr (+ ptr len))
            (qdloop (+ i 1)))))
    (let anloop ((i 0))
      (if (< i ancount)
          (receive (name namelen)
              (get-name buf ptr)
            (vector-set! (vector-ref dnsp 3) i ptr)
            (set! ptr (+ ptr namelen 10
                         (get-u16be buf (+ ptr namelen 8))))  ; RDLENGTH
            (anloop (+ i 1)))))
    (let nsloop ((i 0))
      (if (< i nscount)
          (receive (name namelen)
              (get-name buf ptr)
            (vector-set! (vector-ref dnsp 4) i ptr)
            (set! ptr (+ ptr namelen 10
                         (get-u16be buf (+ ptr namelen 8))))  ; RDLENGTH
            (nsloop (+ i 1)))))
    (let arloop ((i 0))
      (if (< i arcount)
          (receive (name namelen)
              (get-name buf ptr)
            (vector-set! (vector-ref dnsp 5) i ptr)
            (set! ptr (+ ptr namelen 10
                         (get-u16be buf (+ ptr namelen 8))))  ; RDLENGTH
            (arloop (+ i 1)))))
    dnsp))
     

(define (show-dns-packet vec len)
  (define (signer-name->string vec offset)
    (string-join
     (let loop ((i offset)
                (labels (list)))
       (let1 n (get-u8 vec i)
         (if (= n 0)
             (reverse labels)
             (loop (+ i n 1)
                   (cons (u8vector->string vec (+ i 1) (+ i 1 n))
                         labels)))))
     "."))
    

  (define (unixtime->iso8601-string sec)
    (date->string (time-utc->date (make-time time-utc 0 sec)) "~4"))
    
  (define (show-query vec offset)
    (receive (qname qtype qclass len)        ; RFC1035 4.1.2
	(parse-question-section vec offset)
      (format #t "qame=~a, qtype=~a, qclass=~a, length=~a\n"
	      qname qtype qclass len)
      len))
  (define (show-rr vec offset)
    (receive (name namelen)
	(get-name vec offset)
      (format #t "name=~a, type=~a, class=~a, ttl=~a, rdlength=~a\n"
	      name
	      (get-u16be vec (+ offset 2))
	      (get-u16be vec (+ offset 4))
	      (get-u32be vec (+ offset 6))
	      (get-u16be vec (+ offset 10)))
      (let ((qtype (get-u16be vec (+ offset 2)))
            (n (+ offset 12)))
        (cond ((= qtype 46)
               (format #t (string-join
                           '("typecodered=~a, algo=~a, labels=~a,"
                             "origianalttl=~a, expire=~a, inception=~a,"
                             "keytag=~a, signer=~a"
                             "\n"))
                       (get-u16be vec (+ n 0))
                       (get-u8 vec (+ n 2))
                       (get-u8 vec (+ n 3))
                       (get-u32be vec (+ n 4))
                       (unixtime->iso8601-string (get-u32be vec (+ n 8)))
                       (unixtime->iso8601-string (get-u32be vec (+ n 12)))
                       (get-u16be vec (+ n 16))
                       (signer-name->string vec (+ n 18))
                       ))
              ))))
  (print "----------------------------")
  (format #t "ID = ~a\n" (get-u16be vec 0))
  (format #t "QR=~a, " (if (logbit? 7 (get-u8 vec 2))
                           "(1)response"
                           "(0)query"))
  (format #t "AA=~d, " (if (logbit? 2 (get-u8 vec 2)) 1 0))
  (format #t "TC=~d, " (if (logbit? 1 (get-u8 vec 2)) 1 0))
  (format #t "RD=~d, " (if (logbit? 0 (get-u8 vec 2)) 1 0))
  (format #t "RA=~d, " (if (logbit? 7 (get-u8 vec 3)) 1 0))
  (format #t "RCODE=(~d)~a\n"
          (bit-field (get-u8 vec 3) 0 4)
          (case (bit-field (get-u8 vec 3) 0 4)
            ((0) "NOERROR")    ; No error condition
            ((1) "FORMERR")    ; Format error
            ((2) "SERVFAIL")   ; Server failure
            ((3) "NXDOMAIN")   ; Name Error
            ((4) "NOTIMP")     ; Not Implemented
            (else "unknown")))
  (format #t "QDCOUNT=~a, " (get-u16be vec 4))
  (format #t "ANCOUNT=~a, " (get-u16be vec 6))
  (format #t "NSCOUNT=~a, " (get-u16be vec 8))
  (format #t "ARCOUNT=~a\n" (get-u16be vec 10))
  (let ((dnsp (parse-dns-packet0 vec len)))
    (print "Question:")
    (show-query (vector-ref dnsp 0) (vector-ref (vector-ref dnsp 2) 0))
    (print "Answer:")
    (for-each (cut show-rr (dns-packet-buffer dnsp) <>)
              (vector-ref dnsp 3))
    (print "Authority:")
    (for-each (cut show-rr (dns-packet-buffer dnsp) <>)
              (vector-ref dnsp 4))
    (print "Additional:")
    (for-each (cut show-rr (dns-packet-buffer dnsp) <>)
              (vector-ref dnsp 5))
    ))

(define (resolve domain)
  ())

;(send-dns-packet)
;(show-dns-packet (send-dns-packet (make-dns-packet)))
;(resolve "www.kame.net")
;(print (make-qname "www.kame.net"))

(define *default-name-server* #f)

(define (dns-read-resolv-conf)
  (call-with-input-file "/etc/resolv.conf"
    (lambda (port)
      (for-each (lambda (line)
		  (let1 words (string-split (string-trim line) #\space)
		    (if (string=? "nameserver" (car words))
			(set! *dns-server* (cadr words)))))
		(port->string-list port)))))

(define (dns-server) *dns-server*)

(provide "femto.dns")
