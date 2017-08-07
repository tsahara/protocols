(use binary.io)
(use gauche.collection)
(use gauche.uvector)
(use srfi-60)

(define (sha1 string)
  (define (fill-padding msg)
    (u8vector-append msg
		     (u8vector #x80)
		     (make-u8vector (modulo (- 64 (+ (u8vector-length msg) 9))
					    64)
				    0)
		     (let1 v (make-u8vector 8)
		       (put-u64be! v 0 (* 8 (u8vector-length msg)))
		       v)))

  (define (rotl count number)
    (rotate-bit-field number count 0 32))

  (define (f t x y z)
    (cond ((< t 20) (logxor (logand x y)
			    (logand (lognot x) z)))
	  ((< t 40) (logxor x y z))
	  ((< t 60) (logxor (logand x y) (logand x z) (logand y z)))
	  (else     (logxor x y z))))

  (define (K t)
    (cond ((< t 20) #x5a827999)
	  ((< t 40) #x6ed9eba1)
	  ((< t 60) #x8f1bbcdc)
	  (else     #xca62c1d6)))

  (define (mod32 n)
    (modulo n (expt 2 32)))

  ;; FIPS180-4 6.1.2
  (let* ((msg (fill-padding (string->u8vector string)))
	 (N   (/ (u8vector-length msg) 64))
	 (H   (vector #x67452301
		      #xefcdab89
		      #x98badcfe
		      #x10325476
		      #xc3d2e1f0)))

    ;; For i=0 to N-1:
    (dotimes (i N)

      ;; message (+ paddings) are parsed into N 512-bit blocks
      ;; M is a vector of 16 32-bit integers.
      (let ((M (vector-tabulate 16 (lambda (j)
				     (get-u32be msg (+ (* i 64) (* j 4))))))
	    (W (make-vector 80)))

	;; 1. Prepare the message schedule
	(dotimes (t 80)
	  (vector-set! W t
		       (if (< t 16)
			   (vector-ref M t)
			   (rotl 1 (logxor (vector-ref W (- t 3))
					   (vector-ref W (- t 8))
					   (vector-ref W (- t 14))
					   (vector-ref W (- t 16)))))))

	;; 2. Initialize the five working variables
	(let ((a (vector-ref H 0))
	      (b (vector-ref H 1))
	      (c (vector-ref H 2))
	      (d (vector-ref H 3))
	      (e (vector-ref H 4))
	      (T #f))

	  ;; 3. For t=0 to 79
	  (dotimes (t 80)
	    (set! T (+ (rotl 5 a)
		       (f t b c d)
		       e
		       (K t)
		       (vector-ref W t)))
	    (set! e d)
	    (set! d c)
	    (set! c (rotl 30 b))
	    (set! b a)
	    (set! a T))

	  ;; 4. Compute hash value
	  (vector-set! H 0 (mod32 (+ a (vector-ref H 0))))
	  (vector-set! H 1 (mod32 (+ b (vector-ref H 1))))
	  (vector-set! H 2 (mod32 (+ c (vector-ref H 2))))
	  (vector-set! H 3 (mod32 (+ d (vector-ref H 3))))
	  (vector-set! H 4 (mod32 (+ e (vector-ref H 4)))))))

    (let1 digest (make-u8vector 20)
      (put-u32be! digest  0 (vector-ref H 0))
      (put-u32be! digest  4 (vector-ref H 1))
      (put-u32be! digest  8 (vector-ref H 2))
      (put-u32be! digest 12 (vector-ref H 3))
      (put-u32be! digest 16 (vector-ref H 4))
      digest)))

(define (fill-padding-512bits msg)
  (u8vector-append msg
		   (u8vector #x80)
		   (make-u8vector (modulo (- 64 (+ (u8vector-length msg) 9))
					  64)
				  0)
		   (let1 v (make-u8vector 8)
		     (put-u64be! v 0 (* 8 (u8vector-length msg)))
		     v)))

(define (fill-padding-1024bits msg)
  (u8vector-append msg
		   (u8vector #x80)
		   (make-u8vector (modulo (- 64 (+ (u8vector-length msg) 9))
					  64)
				  0)
		   (let1 v (make-u8vector 8)
		     (put-u64be! v 0 (* 8 (u8vector-length msg)))
		     v)))

(define (rotr count number)
  (rotate-bit-field number (- count) 0 32))

(define (shr n x)
  (ash x (- n)))

(define (sigma0 x)
  (logxor (rotr 1 x) (rotr 8 x) (shr 7 x)))

(define (sigma1 x)
  )

(define (sha string
	     :key message-block-byte-length fill-padding H)
  (define (rotl count number)
    (rotate-bit-field number count 0 32))

  (define (f t x y z)
    (cond ((< t 20) (logxor (logand x y)
			    (logand (lognot x) z)))
	  ((< t 40) (logxor x y z))
	  ((< t 60) (logxor (logand x y) (logand x z) (logand y z)))
	  (else     (logxor x y z))))

  (define (K t)
    (cond ((< t 20) #x5a827999)
	  ((< t 40) #x6ed9eba1)
	  ((< t 60) #x8f1bbcdc)
	  (else     #xca62c1d6)))

  (define (mod32 n)
    (modulo n (expt 2 32)))

  ;; FIPS180-4 6.2.2 (SHA256)
  (let* ((msg (fill-padding (string->u8vector string)))
	 (N   (/ (u8vector-length msg) 64)))

    ;; For i=0 to N-1:
    (dotimes (i N)

      ;; message (+ paddings) are parsed into N 512-bit blocks
      ;; M is a vector of 16 32-bit integers.
      (let ((M (vector-tabulate 16 (lambda (j)
				     (get-u32be msg (+ (* i 64) (* j 4))))))
	    (W (make-vector 80)))

	;; 1. Prepare the message schedule
	(dotimes (t 80)
	  (vector-set! W t
		       (if (< t 16)
			   (vector-ref M t)
			   (+ (sigma1 (vector-ref W (- t 2)))
			      (vector-ref W (- t 7))
			      (sigma0 (vector-ref W (- t 15)))
			      (vector-ref W (- t 16))))))

	;; 2. Initialize the five working variables
	(let ((a (vector-ref H 0))
	      (b (vector-ref H 1))
	      (c (vector-ref H 2))
	      (d (vector-ref H 3))
	      (e (vector-ref H 4))
	      (T #f))

	  ;; 3. For t=0 to 79
	  (dotimes (t 80)
	    (set! T (+ (rotl 5 a)
		       (f t b c d)
		       e
		       (K t)
		       (vector-ref W t)))
	    (set! e d)
	    (set! d c)
	    (set! c (rotl 30 b))
	    (set! b a)
	    (set! a T))

	  ;; 4. Compute hash value
	  (vector-set! H 0 (mod32 (+ a (vector-ref H 0))))
	  (vector-set! H 1 (mod32 (+ b (vector-ref H 1))))
	  (vector-set! H 2 (mod32 (+ c (vector-ref H 2))))
	  (vector-set! H 3 (mod32 (+ d (vector-ref H 3))))
	  (vector-set! H 4 (mod32 (+ e (vector-ref H 4)))))))

    (let1 digest (make-u8vector 20)
      (put-u32be! digest  0 (vector-ref H 0))
      (put-u32be! digest  4 (vector-ref H 1))
      (put-u32be! digest  8 (vector-ref H 2))
      (put-u32be! digest 12 (vector-ref H 3))
      (put-u32be! digest 16 (vector-ref H 4))
      digest)))

(define (sha256 string)
  (sha string
       :message-block-byte-length 64
       :fill-padding fill-padding-512bits
       :H (vector #x6a09e667
		  #xbb67ae85
		  #x3c6ef372
		  #xa54ff53a
		  #x510e527f
		  #x9b05688c
		  #x1f83d9ab
		  #x5be0cd19)
       ))

(define (u8vector->hexstring uv)
  (string-join (map (cut format "~2,'0x" <>) uv) ""))

(define (main args)
  (print (u8vector->hexstring (sha256 (port->string (current-input-port))))))
