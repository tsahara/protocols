(use gauche.collection)
(use gauche.uvector)

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

(define (md5 string)
  (let* ((padlen (md5-padding-length (string-length string)))
	 (uv     (u8vector-append (string->u8vector string)
				  (u8vector #x80)
				  (make-u8vector (- padlen 1) 0)
				  ))))


  (hexstring->u8vector "d41d8cd98f00b204e9800998ecf8427e"))

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
