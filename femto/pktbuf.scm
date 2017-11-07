(define-module femto.pktbuf
  (use gauche.uvector)
  (export make-pktbuf
          pktbuf-append-byte
          pktbuf-append-u8
          pktbuf-append-u8vector
          pktbuf-append-u16
          pktbuf-append-u24
          pktbuf-append-u32
          pktbuf-empty?
          pktbuf-prepend
          pktbuf-read-u8
          pktbuf-size
          pktbuf->string
          pktbuf->u8vector
          ))
(select-module femto.pktbuf)

(define (make-pktbuf . initial)
  (if (null? initial)
      (cons #f #f)
      (cons initial initial)))

(define (pktbuf-append-u8 pktbuf n)
  (pktbuf-append-u8vector pktbuf (u8vector (bit-field n 0 8))))

(define pktbuf-append-byte pktbuf-append-u8)

(define (pktbuf-append-u16 pktbuf n)
  (pktbuf-append-u8vector pktbuf (u8vector (bit-field n 8 16)
                                           (bit-field n 0  8))))

(define (pktbuf-append-u24 pktbuf n)
  (pktbuf-append-u8vector pktbuf (u8vector (bit-field n 16 24)
                                           (bit-field n  8 16)
                                           (bit-field n  0  8))))

(define (pktbuf-append-u32 pktbuf n)
  (pktbuf-append-u8vector pktbuf (u8vector (bit-field n 24 32)
                                           (bit-field n 16 24)
                                           (bit-field n  8 16)
                                           (bit-field n  0  8))))

(define (pktbuf-append-u8vector pktbuf vec)
  (if (> (u8vector-length vec) 0)
      (if (pktbuf-empty? pktbuf)
          (let ((l (list vec)))
            (set-car! pktbuf l)
            (set-cdr! pktbuf l))
          (let ((l (list vec)))
            (set-cdr! (cdr pktbuf) l)
            (set-cdr! pktbuf l)))))

(define (pktbuf-empty? pktbuf)
  (not (car pktbuf)))

(define (pktbuf-read-u8 pktbuf)
  (if (pktbuf-empty? pktbuf)
      #f
      (let ((v (caar pktbuf)))
        (if (> (u8vector-length v) 1)
            (set-car! (car pktbuf) (u8vector-copy v 1))
            (if (null? (cdar pktbuf))
                (begin (set-car! pktbuf #f)
                       (set-cdr! pktbuf #f))
                (set-car! pktbuf (cdar pktbuf))))
        (u8vector-ref v 0))))

(define (pktbuf-size pktbuf)
  (if (pktbuf-empty? pktbuf)
      0
      (apply + (map u8vector-length (car pktbuf)))))

(define (pktbuf->string pktbuf)
  (u8vector->string (pktbuf->u8vector pktbuf)))

(define (pktbuf->u8vector pktbuf)
  (if (pktbuf-empty? pktbuf)
      (u8vector)
      (let loop ((v (make-u8vector (pktbuf-size pktbuf)))
                 (l (car pktbuf))
                 (offs 0))
        (if (pair? l)
            (begin (u8vector-copy! v offs (car l))
                   (loop v (cdr l) (+ offs (u8vector-length (car l)))))
            v))))

(define (pktbuf-prepend pktbuf a)
  (cond ((pktbuf-empty? a) pktbuf)
        ((pktbuf-empty? pktbuf) (begin (set-car! pktbuf (car a))
                                       (set-cdr! pktbuf (cdr a))
                                       pktbuf))
        (else (begin (set-cdr! (cdr a) (car pktbuf))
                     (set-car! pktbuf (car a))
                     pktbuf))))

(provide "femto.pktbuf")
