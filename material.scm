(use binary.io)
(use gauche.collection)
(use gauche.net)
(use gauche.uvector)
(use srfi-1)

(define (ipv6-address->string bytes offset)
  (inet-address->string (u8vector-copy bytes offset (+ offset 16)) AF_INET6))

(define (show-hexdump bytes)
  (for-each (cut format #t "~2,'0x " <>) bytes)
  (print))

(define (show-ipv6-packet bytes)
  (if (< (u8vector-length bytes) 40)
      (begin
	(format #t "error: too short ipv6 packet\n")
	(show-hexadump bytes))
      (begin
	(for-each print
		  `((ipv6
		     (version 6)
		     (traffic-class ,(bit-field (get-u32 bytes 0) 28 20))
		     (flow-label ,(bit-field (get-u32 bytes 0) 20 0))
		     (payload-length ,(get-u16 bytes 4))
		     (next-header ,(get-u8 bytes 6))
		     (hop-limit ,(get-u8 bytes 7))
		     (src ,(ipv6-address->string bytes 8))
		     (dst ,(ipv6-address->string bytes 24))
		     )))
	(case (get-u8 bytes 6)
	  ((17) (show-udp-packet (u8vector-copy bytes 40))))
	)))

(define (show-udp-packet bytes)
  (begin
    (for-each print
	      `((udp
		 (srcport  ,(get-u16 bytes 0))
		 (dstport  ,(get-u16 bytes 2))
		 (length   ,(get-u16 bytes 4))
		 (checksum ,(get-u16 bytes 6)))))
    (let ((len     (get-u16 bytes 4))
	  (payload (u8vector-copy bytes 8)))
      (if (< len (u8vector-length bytes))
	(format #t "udp packet has extra bytes! (length field is ~a but we got ~a bytes packet\n"
		len (u8vector-length bytes)))
      (if (> len (u8vector-length bytes))
	(format #t "~a bytes missing from udp packet (length field is ~a but we have only ~a bytes\n"
		len (u8vector-length bytes)))
      (case (get-u16 bytes 2)
	((547) (show-dhcp6-packet payload))
	))))

(define (u8vector->hexa uv start)
  (string-join (map (cut number->string <> 16)
		    (u8vector-copy uv start))
	       " "))

(define (show-dhcp6-packet bytes)
  (define dhcp6-msgtype-alist
    '((1  . solicit)
      (2  . advertise)
      (3  . request)
      (4  . confirm)
      (5  . renew)
      (6  . rebind)
      (7  . reply)
      (8  . release)
      (9  . decline)
      (10 . reconfigure)
      (11 . information-request)
      (12 . relay-forw)
      (13 . relay-repl)
      (14 . leasequery)
      (15 . leasequery-reply)
      (16 . leasequery-done)
      (17 . leasequery-data)
      (18 . reconfigure-request)
      (19 . reconfigure-reply)
      ))

  (define dhcp6-options-alist
    '((1  . option-clientid)
      (6  . option-oro)))

  (define (dhcp6-option-code->symbol code)
    (let1 p (assq code dhcp6-options-alist)
      (if (pair? p)
	  (cdr p)
	  (format #f "(unknown-dhcp6-option-~d)" code))))

  (define (dhcp6-parse-a-option bytes)
    (let ((code (get-u16 bytes 0))
	  (len  (get-u16 bytes 2)))
      (values len
	      (case code
		((1)  `(option-clientid
			(duid ,(u8vector->hexa bytes 2))))
		((6)  `(option-oro
			,(map (lambda (i)
				(dhcp6-option-code->symbol (get-u16 bytes i)))
			      (iota len 4 2))))
		((8)  `(option-elapsed-time
			,(/ (get-u16 bytes 4) 100)))
		((25) `(option-ia-pd
			(iaid ,(get-u32 bytes 4))
			(t1 ,(get-u32 bytes 8))
			(t2 ,(get-u32 bytes 12))
			(ia-pd-options ...)))
			
		(else `((option-code ,code)
			(option-len  ,len)
			(option-data ,(u8vector->hexa bytes 2))))))))

  ;; XXX relay messages are in different format
  (print `(dhcp6
	   (msg-type ,(assq (get-u8 bytes 0) dhcp6-msgtype-alist))
	   (transaction-id ,(bit-field (get-u32 bytes 0) 0 24))
	   ,(reverse (let loop ((opts    (u8vector-copy bytes 4))
				(results '()))
		       (if (= (u8vector-length opts) 0)
			   results
			   (receive (len dump)
			       (dhcp6-parse-a-option opts)
			     (loop (u8vector-copy opts (+ 4 len))
				   (cons dump results)))))))))

(define (show-packet bytes)
  (if (< (u8vector-length bytes) 1)
      (begin
	(print "(too short)")
	(show-hexdump bytes))
      (case (bit-field (get-u8 bytes 0) 4 8)
	((6)  (show-ipv6-packet bytes))
	(else (show-hexdump bytes)))))

(define (read-hex-dump)
  (define (line->hexlist line)
    (rxmatch-let (#/^\s+0x[0-9]+: ((?: [0-9a-f]{4})+)\s*$/ line)
	(_ hexa)
      (concatenate
       (map (lambda (s)
	      (case (string-length s)
		((0) (list))
		((2) (list (string->number s 16)))
		((4) (list (string->number (substring s 0 2) 16) 
			   (string->number (substring s 2 4) 16)))))
	    (string-split hexa " ")))))

  (let loop ((l (list)))
    (let1 line (read-line)
      (if (eof-object? line)
	  (list->u8vector l)
	  (loop (append l (line->hexlist line)))))))

(define (main args)
  (default-endian 'big-endian)
  (show-packet (read-hex-dump))
  )
