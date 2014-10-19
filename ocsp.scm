(use gauche.uvector)

(define (parse-oid uvec)
  (let1 byte0 (u8vector-ref uvec 0)
    (let ((id1 (quotient byte0 40))
	  (id2 (remainder byte0 40)))
      (list id1 id2)
      )))

(define (parse-tag uvec)
  (let* ((tc  (u8vector-ref uvec 0))
	 (len (u8vector-ref uvec 1))
	 (val (u8vector-copy uvec 2 (+ 2 len))))
    (let ((class      (bit-field tc 6 8))
	  (structured (bit-field tc 5 6))
	  (tag        (bit-field tc 0 5)))
      (case tag
	((6)  (list 'object-identifier (parse-oid val)))
	((16) (list 'sequence (parse-tag val)))
	(else (format #f "unknown tag ~a" tag))))))

(define (ocsp-show filename)
  (let1 bytes (string->u8vector (call-with-input-file filename port->string))
    (parse-tag bytes)))

(define (main args)
  (ocsp-show "data/ocsp-req.der"))
