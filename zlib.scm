(use scheme.bitwise)
(use scheme.bytevector)
(use gauche.sequence)
(use gauche.uvector)


(define *bitorder-table*
  (let ((table (make-bytevector 256))
        (lbits #u8(#x00 #x80 #x40 #xc0 #x20 #xa0 #x60 #xe0
                        #x10 #x90 #x50 #xd0 #x30 #xb0 #x70 #xf0))
        (hbits  #u8(#x00 #x08 #x04 #x0c #x02 #x0a #x06 #x0e
                         #x01 #x09 #x05 #x0d #x03 #x0b #x07 #x0f)))
    (dotimes (h 16)
      (dotimes (l 16)
        (bytevector-u8-set! table
                            (+ (* h 16) l)
                            (+ (bytevector-u8-ref hbits h)
                               (bytevector-u8-ref lbits l)))))
    table))

;; reverse the order of least significant `num` bits.
(define (reverse-bits bits num)
  (arithmetic-shift (bytevector-u8-ref *bitorder-table* bits)
                    (- num 8)))

(define (<< a n)
  (arithmetic-shift a n))

(define (inflate uv)
  (let ((byteoffset 0)
        (bitoffset 0)
        (output-buffer (make-bytevector 65536))
        (output-byte-offset 0))
    (define (readbit!)
      (let1 byte (u8vector-ref uv byteoffset)
        (if (< bitoffset 7)
            (let1 bit (bit-field byte bitoffset (+ bitoffset 1))
              (inc! bitoffset)
              bit)
            (let1 bit (bit-field byte 7 8)
              (inc! byteoffset)
              (set! bitoffset 0)
              bit))))
    (define (readbits! k)
      (let1 tobit (+ bitoffset k)
        (if (<= tobit 8)
            (let1 bits (bit-field (u8vector-ref uv byteoffset) bitoffset tobit)
              (if (< tobit 8)
                  (set! bitoffset tobit)
                  (begin
                    (inc! byteoffset)
                    (set! bitoffset 0)))
              bits)
            (let* ((twobyte (bitwise-ior (u8vector-ref uv byteoffset)
                                         (arithmetic-shift
                                          (u8vector-ref uv (+ byteoffset 1))
                                          8)))
                   (bits (bit-field twobyte bitoffset tobit)))
              (inc! byteoffset)
              (set! bitoffset (remainder tobit 8))
              bits))))
    (define (reverse-readbits! k)
      (reverse-bits (readbits! k) k))

    (define (get-output-buffer)
      (bytevector-copy output-buffer 0 output-byte-offset))
    (define (writebyte n)
      (bytevector-u8-set! output-buffer output-byte-offset n)
      (inc! output-byte-offset))
    (define (write-backward-reference dist len)
      (let ((pos (- output-byte-offset dist)))
        (dotimes (i len)
          (writebyte (bytevector-u8-ref output-buffer (+ pos i))))))

    (define (read-literal/length)
      (let1 prefix (reverse-readbits! 5)
        (cond ((<= prefix #b00101)  ;; 00000-00101, 256-279, 7bits
               (+ (<< prefix 2) 256 (reverse-readbits! 2)))
              ((= prefix #b11000)  ;; 11000, 280-287, 8bits
               (+ (<< (- prefix #b11000) 3) 280 (reverse-readbits! 3)))
              ((>= prefix 25) ;; 11001-11111, 144-255, 9bits
               (+ (<< (- prefix #b11001) 4) 144 (reverse-readbits! 4)))
              (else           ;; 00110-10111, 0-143, 8bits
               (+ (<< (- prefix #b00110) 3) (reverse-readbits! 3))))))

    (define (read-length-bits! code)
      ;; RFC1951 3.2.5 the first table
      (cond ((< code 265) (- code 254))
            ((= code 285) 258)
            (else
             (let* ((ebl (quotient (- code 261) 4)) ;; extra bit length
                    (extra-bits (reverse-readbits! ebl)))
               (+ 3 (ash (- code 257 (* ebl 4)) ebl) extra-bits)))))

    (define (read-distance-extra-bits! code)
      (if (< code 4)
          (+ code 1)
          (let* ((ebl (quotient (- code 2) 2))  ;; extra bit length
                 (extra-bits (readbits! ebl)))
            (+ 1 (ash (- code (* ebl 2)) ebl) extra-bits))))

    (define (read-distance-code!)
      (read-distance-extra-bits! (reverse-readbits! 5)))

    (define (fixed-huffman-block)
      (format #t "compressed with fixed Huffman codes~%")
      (let loop ((a (read-literal/length)))
        (format #t "-> ~a~%" a)
        (unless (= a 256)  ;; end-of-block
          (if (< a 256)
              ;; a literal byte
              (writebyte a)
              ;; <length, backward distance> pair
              (let ((len (read-length-bits! a)))
                (let1 distance (read-distance-code!)
                  (format #t "pair <len=~a, distance=~a>~%" len distance)
                  (write-backward-reference distance len)
                  )))
          (loop (read-literal/length)))))

    (define (dynamic-huffman-block)
      (define code-length-alphabets
        #(16 17 18 0 8 7 9 6 10 5 11 4 12 3 13 2 14 1 15))

      (define (read-huffman-bits tree)
        (let loop ((node tree))
          (let1 b (readbit!)
            (format #t "~b" b)
            (let1 next (if (= b 0)
                           (car node)
                           (cdr node))
              (if (pair? next)
                  (loop next)
                  next)))))

      (format #t "compressed with dynamic Huffman codes~%")
      (let* ((hlit  (readbits! 5))
             (hdist (readbits! 5))
             (hclen (readbits! 4))
             (code-length-huffman-tree #f)
             (literal/length-huffman-tree #f)
             (distance-huffman-tree #f))
        (format #t "HLIT=~a HDIST=~a HCLEN=~a~%" hlit hdist hclen)

        ;; 1. Read code lengths for the code length alphabet.
        (format #t "code length alphabet:~%")
        (let ((bitlens (make-vector (vector-length code-length-alphabets)
                                    0)))
          (dotimes (i (+ hclen 4))
            (let1 codelen (readbits! 3)
              (format #t "  alphabet=~a len=~a~%"
                      (vector-ref code-length-alphabets i)
                      codelen)
              (vector-set! bitlens i codelen)))
          (format #t "hclens = ~a~%" bitlens)
          (set! code-length-huffman-tree
                (build-huffman-tree
                 (map cons
                      (vector->list code-length-alphabets)
                      (vector->list bitlens))))
          (format #t "Code Length Huffman Tree:~%")
          (print-huffman-tree code-length-huffman-tree))

        ;; 2. Read code lengths for the literal/length & distance alphabet.
        (format #t "reading literal length alphabets...~%")
        (let1 codelens (make-vector (+ hlit hdist 258) 0)
          (let loop ((i 0)
                     (prev #f))
            (if (< i (vector-length codelens))
                (let1 bits (read-huffman-bits code-length-huffman-tree)
                  (if (< bits 16)
                      (begin
                        (format #t "  ~a~%" bits)
                        (vector-set! codelens i bits)
                        (loop (+ i 1) bits))
                      (begin
                        ;; check (< bits 18)...?
                        (let ((nbits (list-ref '(2 3 7) (- bits 16)))
                              (base  (list-ref '(3 3 11) (- bits 16))))
                          (let1 rep (+ base (readbits! nbits))
                            (format #t "  ~a:(copy ~a times)~%" bits rep)
                            (dotimes (j rep)
                              (vector-set! codelens (+ i j) prev))
                            (loop (+ i rep) prev))))))))
          (when #f
            (dotimes (i (vector-length codelens))
              (if (= (modulo i 10) 0)
                  (format #t "~%~3d  " i))
              (format #t "~2d, " (vector-ref codelens i)))
            (newline))

          (set! literal/length-huffman-tree
                (build-huffman-tree
                 (map-with-index cons
                                 (vector->list
                                  (vector-copy codelens 0 (+ hlit 257))))))
          (format #t "Literal/Length Huffman Tree:~%")
          ;;(print-huffman-tree literal/length-huffman-tree)

          (set! distance-huffman-tree
                (build-huffman-tree
                 (map-with-index cons
                                 (vector->list
                                  (vector-copy codelens
                                               (+ hlit 257)
                                               (vector-length codelens))))))
          (format #t "Distance Huffman Tree:~%")
          ;;(print-huffman-tree distance-huffman-tree)
          )

        ;; 3. Read Huffman codes
        (format #t "Reading Huffman codes...~%")
        (let loop ((a (read-huffman-bits literal/length-huffman-tree)))
          (format #t "-> ~a~%" a)
          (unless (= a 256)  ;; end-of-block
            (if (< a 256)
                ;; a literal byte
                (writebyte a)
                ;; <length, backward distance> pair
                (let ((len (read-length-bits! a)))
                  (let* ((dc (read-huffman-bits distance-huffman-tree))
                         (distance (read-distance-extra-bits! dc)))
                    (format #t "pair <len=~a, distance=~a>~%" len distance)
                    (write-backward-reference distance len)
                    )))
            (loop (read-huffman-bits literal/length-huffman-tree))))
        ))

    (while (< byteoffset (u8vector-length uv))
      (let* ((bfinal (readbit!))
             (btype  (readbits! 2)))
        (format #t "bfinal=~a btype=~a~%" bfinal btype)

        (case btype
          ((0) (no-compression-block))
          ((1) (fixed-huffman-block))
          ((2) (dynamic-huffman-block))
          (else (errorf "unknown BTYPE(~a)" btype)))

        (when bfinal
          (set! byteoffset (u8vector-length uv)))))
    (get-output-buffer)))

(define (zlib-decompress uv)
  (define (bit-unset? index n)
    (not (bit-set? index n)))

  (when (< (u8vector-length uv) 8)
    (raise "too short data"))
  (let ((cmf (u8vector-ref uv 0))
        (flg (u8vector-ref uv 1)))
    (unless (= cmf #x78)
      (errorf "unknown CMF 0x~x (must be 0x78)" cmf))
    (unless (= (remainder (+ (* cmf 256) flg) 31) 0)
      (errorf "bad CMF+FLG value!"))
    (unless (bit-unset? 5 flg)
      (errorf "FDICT=1 is not supported")))

  (let1 compressed_data (u8vector-copy uv 2 (- (u8vector-length uv) 4))
    (let1 data (inflate compressed_data)
      ;; (when (adler32 data)
      ;;    (raise "bad checksum"))
      data)))

(define (main args)
  (with-input-from-file (cadr args)
    (lambda ()
      (let1 bvec (read-bytevector 65536)
        (write-bytevector (zlib-decompress bvec))))))

;; "length-list" is a list of pairs of (alphabet . code-length).
;; huffman-tree is a huffman node.
;; huffman node is
;;   (a) a cons that car/cdr is a huffman node or
;;   (b) an alphabet.
(define (build-huffman-tree length-list)
  (let ((al (sort (filter (lambda (p) (> (cdr p) 0)) length-list)
                  (lambda (a b)
                    (or (< (cdr a) (cdr b))
                        (and (= (cdr a) (cdr b))
                             (< (car a) (car b))))))))
    (let loop ((curbitlen 0))
      (if (null? al)
          #f
          (let ((sym    (car (car al)))
                (bitlen (cdr (car al))))
            (if (= curbitlen bitlen)
                (begin
                  (pop! al)
                  sym)
                (let* ((left  (loop (+ curbitlen 1)))
                       (right (loop (+ curbitlen 1))))
                  (cons left right))))))))

(define (print-huffman-tree tree)
  (let loop ((node tree)
             (curbits 0)
             (curbitlen 0))
    (cond ((null? node) )
          ((pair? node)
           (loop (car node) (ash curbits 1) (+ curbitlen 1))
           (loop (cdr node) (+ (ash curbits 1) 1) (+ curbitlen 1)))
          (else
           (format #t "~v,'0b -> ~a~%" curbitlen curbits node)))))
