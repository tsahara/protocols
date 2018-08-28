(use binary.io)
(use gauche.sequence)
(use gauche.uvector)
(use srfi-151)

;; This implementation is based on RFC1321.

(define (md5-padding-length len)
  (modulo (- 0 8 len) 64))

(define (u8vector->hexstring uv)
  (string-join (map (cut format "~2,'0x" <>) uv) ""))

(define (hexstring->u8vector str)
  (let* ((uvlen (/ (string-length str) 2))
	 (uv    (make-u8vector uvlen)))
    (dotimes (i uvlen)
      (u8vector-set! uv i (string->number (substring str
						     (* 2 i)
						     (+ (* 2 i) 2))
					  16)))
    uv))

(define *sine-table*
  (list->u32vector (map (^i (inexact->exact (floor (* (abs (sin i))
						      4294967296))))
			(iota 64 1))))

(define (md5 string)
  (define (make-padding string)
    ;; b = length of the string in bits
    (let* ((b       (* (string-length string) 8))
	   (msglen0 (modulo b 512))
	   (padlen  (if (< msglen0 448)
			(- 448 msglen0)
			(- (+ 512 448) msglen0)))
	   (uv      (make-u8vector (quotient padlen 8))))
      (u8vector-set! uv 0 #x80)
      (u8vector-fill! uv 0 1 (quotient padlen 8))
      uv))

  (define (make-length-bytes string)
    (let ((uv (make-u8vector 8)))
      (put-u64le! uv 0 (* (string-length string) 8))
      uv))

  (define (lognot0 num)
    (logxor num #xffffffff))

  (define (mod32 num)
    (modulo num (expt 2 32)))

  (let* ((padded-message (u8vector-append (string->u8vector string)
					  (make-padding string)
					  (make-length-bytes string)))
	 (N (quotient (u8vector-length padded-message) 4))
	 (M (let1 uv (make-u32vector N)
	      (dotimes (i N)
		(u32vector-set! uv i (get-u32le padded-message (* i 4))))
	      uv))

	 (A #x67452301)
	 (B #xefcdab89)
	 (C #x98badcfe)
	 (D #x10325476)

	 (F (lambda (x y z)
	      (logior (logand x y)
		      (logand (lognot0 x) z))))
	 (G (lambda (x y z)
	      (logior (logand x z)
		      (logand y (lognot0 z)))))
	 (H (lambda (x y z)
	      (logxor x y z)))
	 (I (lambda (x y z)
	      (logxor y (logior x (lognot0 z)))))

	 (T *sine-table*)
	 (X (make-u32vector 16)))

    ;; Process each 16-word block.
    (dotimes (i (quotient N 16))

      ;; Copy block i into X.
      (u32vector-copy! X 0 M (* i 16))

      ;; Save A as AA, B as BB, C as CC, and D as DD.
      (let ((AA A)
	    (BB B)
	    (CC C)
	    (DD D)
	    (f  #f))
	(define (<<< num count)
	  (bit-field-rotate num count 0 32))
	(define (round-op a b c d k s i)
	  (mod32 (+ b (<<< (+ a
			      (f b c d)
			      (u32vector-ref X k)
			      (u32vector-ref T (- i 1)))
			   s))))

	(let-syntax ((ABCD (syntax-rules ()
			     ((_ k s i)
			      (set! A (round-op A B C D k s i)))))
		     (DABC (syntax-rules ()
			     ((_ k s i)
			      (set! D (round-op D A B C k s i)))))
		     (CDAB (syntax-rules ()
			     ((_ k s i)
			      (set! C (round-op C D A B k s i)))))
		     (BCDA (syntax-rules ()
			     ((_ k s i)
			      (set! B (round-op B C D A k s i))))))

	  ;; Round 1.
	  (set! f F)
	  [ABCD  0  7  1]  [DABC  1 12  2]  [CDAB  2 17  3]  [BCDA  3 22  4]
	  [ABCD  4  7  5]  [DABC  5 12  6]  [CDAB  6 17  7]  [BCDA  7 22  8]
	  [ABCD  8  7  9]  [DABC  9 12 10]  [CDAB 10 17 11]  [BCDA 11 22 12]
	  [ABCD 12  7 13]  [DABC 13 12 14]  [CDAB 14 17 15]  [BCDA 15 22 16]

	  ;; Round 2.
	  (set! f G)
	  [ABCD  1  5 17]  [DABC  6  9 18]  [CDAB 11 14 19]  [BCDA  0 20 20]
	  [ABCD  5  5 21]  [DABC 10  9 22]  [CDAB 15 14 23]  [BCDA  4 20 24]
	  [ABCD  9  5 25]  [DABC 14  9 26]  [CDAB  3 14 27]  [BCDA  8 20 28]
	  [ABCD 13  5 29]  [DABC  2  9 30]  [CDAB  7 14 31]  [BCDA 12 20 32]

	  ;; Round 3.
	  (set! f H)
	  [ABCD  5  4 33]  [DABC  8 11 34]  [CDAB 11 16 35]  [BCDA 14 23 36]
	  [ABCD  1  4 37]  [DABC  4 11 38]  [CDAB  7 16 39]  [BCDA 10 23 40]
	  [ABCD 13  4 41]  [DABC  0 11 42]  [CDAB  3 16 43]  [BCDA  6 23 44]
	  [ABCD  9  4 45]  [DABC 12 11 46]  [CDAB 15 16 47]  [BCDA  2 23 48]

	  ;; Round 4.
	  (set! f I)
	  [ABCD  0  6 49]  [DABC  7 10 50]  [CDAB 14 15 51]  [BCDA  5 21 52]
	  [ABCD 12  6 53]  [DABC  3 10 54]  [CDAB 10 15 55]  [BCDA  1 21 56]
	  [ABCD  8  6 57]  [DABC 15 10 58]  [CDAB  6 15 59]  [BCDA 13 21 60]
	  [ABCD  4  6 61]  [DABC 11 10 62]  [CDAB  2 15 63]  [BCDA  9 21 64]

	  (set! A (mod32 (+ A AA)))
	  (set! B (mod32 (+ B BB)))
	  (set! C (mod32 (+ C CC)))
	  (set! D (mod32 (+ D DD)))
	  )))

    (let1 digest (make-u8vector 16)
      (put-u32le! digest  0 A)
      (put-u32le! digest  4 B)
      (put-u32le! digest  8 C)
      (put-u32le! digest 12 D)
      digest)))

(for-each (lambda (pair)
	    (let ((input  (car pair))
		  (output (cdr pair)))
	      (if (string=? (u8vector->hexstring (md5 input)) output)
		  (format #t "md5(~a) => ok\n" input)
		  (format #t "md5(~a) => NG!!!\n" input))))

	  ;; test vectors in RFC1321
	  '(("" . "d41d8cd98f00b204e9800998ecf8427e")
	    ("a" . "0cc175b9c0f1b6a831c399e269772661")
	    ("abc" . "900150983cd24fb0d6963f7d28e17f72")
	    ("message digest" . "f96b697d7cb7938d525a2f31aaf161d0")
	    ("abcdefghijklmnopqrstuvwxyz" ."c3fcd3d76192e4007dfb496cca67e13b")
	    ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" . "d174ab98d277d9f5a5611c2c9f419d9f")
	    ("12345678901234567890123456789012345678901234567890123456789012345678901234567890" . "57edf4a22be3c955ac49da2e2107b67a")))
