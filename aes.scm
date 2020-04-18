(use binary.io)
(use gauche.collection)
(use gauche.uvector)
(use scheme.bitwise)
(use srfi-60)

(load "./util.scm")

;; (key-length rounds)
;; (aes128 (16 10))
;; (aes192 (24 12))
;; (aes256 (32 14))

(define-class <aes-context> ()
  (key-length
   rounds))

(define (make-aes-context type)
  (let* ((ctx    (make <aes-context>))
	 (params (case type
		   ((aes128) '(16 10)))))
    (slot-set! ctx 'key-length (first params))
    (slot-set! ctx 'rounds     (+ (* 4 (slot-ref ctx 'key-length)) 6))
))

(define *sbox*
   #(#u8(#x63 #x7c #x77 #x7b #xf2 #x6b #x6f #xc5
	     #x30 #x01 #x67 #x2b #xfe #xd7 #xab #x76)
       #u8(#xca #x82 #xc9 #x7d #xfa #x59 #x47 #xf0
		#xad #xd4 #xa2 #xaf #x9c #xa4 #x72 #xc0)
       #u8(#xb7 #xfd #x93 #x26 #x36 #x3f #xf7 #xcc
		#x34 #xa5 #xe5 #xf1 #x71 #xd8 #x31 #x15)
       #u8(#x04 #xc7 #x23 #xc3 #x18 #x96 #x05 #x9a
		#x07 #x12 #x80 #xe2 #xeb #x27 #xb2 #x75)
       #u8(#x09 #x83 #x2c #x1a #x1b #x6e #x5a #xa0
		#x52 #x3b #xd6 #xb3 #x29 #xe3 #x2f #x84)
       #u8(#x53 #xd1 #x00 #xed #x20 #xfc #xb1 #x5b
		#x6a #xcb #xbe #x39 #x4a #x4c #x58 #xcf)
       #u8(#xd0 #xef #xaa #xfb #x43 #x4d #x33 #x85
		#x45 #xf9 #x02 #x7f #x50 #x3c #x9f #xa8)
       #u8(#x51 #xa3 #x40 #x8f #x92 #x9d #x38 #xf5
		#xbc #xb6 #xda #x21 #x10 #xff #xf3 #xd2)
       #u8(#xcd #x0c #x13 #xec #x5f #x97 #x44 #x17
		#xc4 #xa7 #x7e #x3d #x64 #x5d #x19 #x73)
       #u8(#x60 #x81 #x4f #xdc #x22 #x2a #x90 #x88
		#x46 #xee #xb8 #x14 #xde #x5e #x0b #xdb)
       #u8(#xe0 #x32 #x3a #x0a #x49 #x06 #x24 #x5c
		#xc2 #xd3 #xac #x62 #x91 #x95 #xe4 #x79)
       #u8(#xe7 #xc8 #x37 #x6d #x8d #xd5 #x4e #xa9
		#x6c #x56 #xf4 #xea #x65 #x7a #xae #x08)
       #u8(#xba #x78 #x25 #x2e #x1c #xa6 #xb4 #xc6
		#xe8 #xdd #x74 #x1f #x4b #xbd #x8b #x8a)
       #u8(#x70 #x3e #xb5 #x66 #x48 #x03 #xf6 #x0e
		#x61 #x35 #x57 #xb9 #x86 #xc1 #x1d #x9e)
       #u8(#xe1 #xf8 #x98 #x11 #x69 #xd9 #x8e #x94
		#x9b #x1e #x87 #xe9 #xce #x55 #x28 #xdf)
       #u8(#x8c #xa1 #x89 #x0d #xbf #xe6 #x42 #x68
		#x41 #x99 #x2d #x0f #xb0 #x54 #xbb #x16)))

(define (subbyte b)
  (u8vector-ref (vector-ref *sbox* (ash b -4))
                (bit-field b 0 4)))

(define (key-expansion! cipher-key expanded-key)
  ;; Nb: block length in words (word=32bits)
  ;; Nk: key length in words
  ;; Nr: number of rounds for that key length
  (let* ((Nb    4)
         (Nk    (/ (bytevector-length cipher-key) 4))
         (Nr    (+ Nk 6))
         (words (make-u32vector (* Nb (+ Nr 1)))))
    (define (word-ref i)
      (u32vector-ref words i))
    (define (word-set! i val)
      (u32vector-set! words i val))
    (define (rotword w)  ;; left rotate by 8 bits
      (logior (ash (bit-field w 0 24) 8)
              (ash w -24)))
    (define (subword w)
      (logior (ash (subbyte (bit-field w 24 32)) 24)
              (ash (subbyte (bit-field w 16 24)) 16)
              (ash (subbyte (bit-field w 8 16)) 8)
              (subbyte (bit-field w 0 8))))
    (define (rcon-word r)
      (ash (if (<= r 8)
               (expt 2 (- r 1))
               (* #x1b (expt 2 (- r 9))))
           24))

    (dotimes (i (u32vector-length words))
      (if (< i Nk)
          ;; first Nk words are just copy of cipher-key.
          (word-set! i (get-u32be cipher-key (* i 4)))

          ;; rest of iterations...
          (cond ((= (modulo i Nk) 0)
                 (word-set! i (logxor (word-ref (- i Nk))
                                      (subword (rotword (word-ref (- i 1))))
                                      (rcon-word (div i Nk)))))
                ((and (> Nk 6) (= (modulo i Nk) 4))
                 (word-set! i (logxor (word-ref (- i Nk))
                                      (subword (word-ref (- i 1))))))
                (else
                 (word-set! i (logxor (word-ref (- i Nk))
                                      (word-ref (- i 1)))))))
      (put-u32be! expanded-key (* i 4) (word-ref i)))))

(define (cbc block iv)
  (dotimes (i (u8vector-length block))
    (u8vector-set! block i (logxor (u8vector-ref block i)
                                   (u8vector-ref iv i)))))

(define (aes-encrypt key iv plaintext)
  (let* ((num-of-rounds     (+ (/ (bytevector-length key) 4) 6))
         (key-byte-length   (* (bytevector-length key) 8))
         (block-byte-length 16)
         (state             (u8vector-copy plaintext))  ;; 128bits
         (expanded-key      (make-u8vector (* (+ num-of-rounds 1)
                                              block-byte-length)))
         (round-key (lambda (i)
                      (u8vector-copy expanded-key (* 4 Nb)
                                     (* i 16)
                                     (* (+ i 1) 16))))
         )
    (define (print-state str)
      (format #t "~a =>~%" str)
      (dotimes (row 4)
        (format #t "~2,'0x ~2,'0x ~2,'0x ~2,'0x~%"
                (u8vector-ref state (+ 0 row))
                (u8vector-ref state (+ 4 row))
                (u8vector-ref state (+ 8 row))
                (u8vector-ref state (+ 12 row)))))
    (define (state-ref row col)
      (u8vector-ref state (+ (* col 4) row)))
    (define (state-set! row col val)
      (u8vector-set! state (+ (* col 4) row) val))

    (define (add-round-key! state expanded-key round)
      (define (round-key row col)
        (u8vector-ref expanded-key (+ (* round 16) (* col 4) row)))
      (dotimes (row 4)
        (dotimes (col 4)
          (state-set! row col (logxor (round-key row col)
                                      (state-ref row col))))))

    (define (sub-bytes! state)
      (dotimes (i (u8vector-length state))
        (u8vector-set! state i (subbyte (u8vector-ref state i)))))

    (define (shift-rows!)
      (let1 tmp (state-ref 1 0)
        (state-set! 1 0 (state-ref 1 1))
        (state-set! 1 1 (state-ref 1 2))
        (state-set! 1 2 (state-ref 1 3))
        (state-set! 1 3 tmp))
      (let ((tmp0 (state-ref 2 0))
            (tmp1 (state-ref 2 1)))
        (state-set! 2 0 (state-ref 2 2))
        (state-set! 2 2 tmp0)
        (state-set! 2 1 (state-ref 2 3))
        (state-set! 2 3 tmp1))
      (let1 tmp (state-ref 3 3)
        (state-set! 3 3 (state-ref 3 2))
        (state-set! 3 2 (state-ref 3 1))
        (state-set! 3 1 (state-ref 3 0))
        (state-set! 3 0 tmp)))

    (define (xtime x)
      (let1 y (ash x 1)
        (if (>= y #x100)
            (logxor y #x11b)
            y)))

    (define (mix-columns!)
      (dotimes (col 4)
        (let* ((a0 (state-ref 0 col))
               (a1 (state-ref 1 col))
               (a2 (state-ref 2 col))
               (a3 (state-ref 3 col))
               (t  (logxor a0 a1 a2 a3)))
          (state-set! 0 col (logxor a0 (xtime (logxor a0 a1)) t))
          (state-set! 1 col (logxor a1 (xtime (logxor a1 a2)) t))
          (state-set! 2 col (logxor a2 (xtime (logxor a2 a3)) t))
          (state-set! 3 col (logxor a3 (xtime (logxor a3 a0)) t)))))

    ;; XXX CBC
    (if iv
        (cbc state iv))

    (key-expansion! key expanded-key)
    (add-round-key! state expanded-key 0)

    ;; Rounds
    (do ((i 1 (+ i 1)))
        ((= i num-of-rounds))
      (sub-bytes! state)
      (shift-rows!)
      (mix-columns!)
      (add-round-key! state expanded-key i))

    ;; Final Round
    (sub-bytes! state)
    (shift-rows!)
    (add-round-key! state expanded-key num-of-rounds)
    state))

#;(let1 r (aes-encrypt (string->u8vector "01234567890123456789012345678901")
                     (string->u8vector "00000000000000000000000000000000")
                     (string->u8vector "abcdefghijklmnop"))
  (print (bytevector->hexadecimal r)))
