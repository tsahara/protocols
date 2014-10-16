(use gauche.collection)
(use gauche.uvector)
(use srfi-60)

(define (arcfour-operate plaintext key)

  (define (swap vec i j)
    (let1 tmp (u8vector-ref vec i)
      (u8vector-set! vec i (u8vector-ref vec j))
      (u8vector-set! vec j tmp)))
      
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

(print
 (map
  (cut number->string <> 16)
  (arcfour-operate (string->u8vector "abcdefghijklmnop")
                   (let1 a (make-u8vector 16)
                     (u8vector-copy! a 0 (string->u8vector "abcdef"))))))
