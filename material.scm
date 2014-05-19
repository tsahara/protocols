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
	)))

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
