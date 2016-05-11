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
