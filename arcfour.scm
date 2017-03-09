(use gauche.collection)
(use gauche.uvector)
(use srfi-60)

(define-class <arcfour> ()
  (key-schedule i j))

(define (arcfour-swap uvec i j)
  (let1 tmp (u8vector-ref uvec i)
    (u8vector-set! uvec i (u8vector-ref uvec j))
    (u8vector-set! uvec j tmp)))

;; key:<u8vector>
(define (make-arcfour key)
  (let ((arcfour (make <arcfour>)))

    ;; 1. initialize key schedule
    (slot-set! arcfour 'key-schedule (list->u8vector (iota 256)))

    ;; 2. combine secret key with schedule
    (let ((schedule (slot-ref arcfour 'key-schedule))
	  (j        0))
      (dotimes (i 256)
	(let1 k (modulo (+ j
			   (u8vector-ref schedule i)
			   (u8vector-ref key (modulo i (u8vector-length key))))
			256)
	  (arcfour-swap schedule i k)
	  (set! j k))))

    ;; 3. initialize i and j.
    (slot-set! arcfour 'i 0)
    (slot-set! arcfour 'j 0)

    arcfour))

(define (arcfour-encrypt arcfour plaintext)
  (let ((ciphertext (make-u8vector (u8vector-length plaintext)))
	(schedule   (slot-ref arcfour 'key-schedule))
	(i          (slot-ref arcfour 'i))
	(j          (slot-ref arcfour 'j)))
    (dotimes (n (u8vector-length plaintext))
      (set! i (modulo (+ i 1) 256))
      (set! j (modulo (+ j (u8vector-ref schedule i)) 256))
      (arcfour-swap schedule i j)
      (u8vector-set! ciphertext
		     n
		     (logxor (u8vector-ref schedule
					   (modulo (+ (u8vector-ref schedule i)
						      (u8vector-ref schedule j))
						   256))
			     (u8vector-ref plaintext n))))
    (slot-set! arcfour 'i i)
    (slot-set! arcfour 'j j)
    ciphertext))

(define (arcfour-operate plaintext key)
  (define (swap uvec i j)
    (let1 tmp (u8vector-ref uvec i)
      (u8vector-set! uvec i (u8vector-ref uvec j))
      (u8vector-set! uvec j tmp)))

  (let ((ciphertext (make-u8vector (u8vector-length plaintext)))
        (schedule   (list->u8vector (iota 256))))

    ;; key is combined with the key schedule
    (let iter1 ((i 0) (j 0))
      (if (< i 256)
          (let1 k (modulo (+ j
                             (u8vector-ref schedule i)
                             (u8vector-ref key
                                           (modulo i (u8vector-length key))))
                          256)
            (swap schedule i k)
            (iter1 (+ i 1) k))))

    ;; encrypt / decrypt
    (let iter2 ((i 0) (j 0) (n 0))
      (if (< n (u8vector-length plaintext))
          (let* ((ni (modulo (+ i 1) 256))
                 (nj (modulo (+ j (u8vector-ref schedule ni)) 256)))
            (swap schedule ni nj)
            (u8vector-set! ciphertext n
                           (logxor (u8vector-ref
                                    schedule
                                    (modulo (+ (u8vector-ref schedule ni)
                                               (u8vector-ref schedule nj))
                                            256))
                                   (u8vector-ref plaintext n)))
            (iter2 ni nj (+ n 1)))))

    ciphertext))

;; compare to "openssl "
;; (8d 41 42 dc 38 3f 55 92 e3 23 c1 4b e8 44 d1 58)
(define (main args)
  (define (parse-key keystr)
    (let* ((keylen (div (string-length keystr) 2))
	   (keyvec (make-u8vector keylen)))
      (dotimes (i keylen)
	(u8vector-set! keyvec i
		       (string->number (substring keystr (* i 2) (* (+ i 1) 2))
				       16)))
      keyvec))

  (unless (= (length args) 2)
    (print "usage: arcfour.scm <key>")
    (exit 1))

  (print
   (map
    (cut number->string <> 16)
    (arcfour-operate (string->u8vector "abcdefghijklmnop")
		     (let1 a (make-u8vector 16)
		       (u8vector-copy! a 0 (string->u8vector "abcdef"))))))

  (let1 key (parse-key (cadr args));;(make-u8vector 16)
;;    (u8vector-copy! key 0 (string->u8vector "abcdef"))
    (let ((arcfour (make-arcfour key)))
      (print
       (map (cut number->string <> 16)
	    (arcfour-encrypt arcfour (string->u8vector "abcdefgh")))
       (map (cut number->string <> 16)
	    (arcfour-encrypt arcfour (string->u8vector "ijklmnop"))))
      )))
