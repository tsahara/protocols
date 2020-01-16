(use gauche.net)
(use gauche.uvector)
(use rfc.hmac)
(use rfc.sha)
(use rfc.uri)

(define (hexadecimal->bytevector str)
  (let* ((uvlen (/ (string-length str) 2))
         (uv    (make-u8vector uvlen)))
    (dotimes (i uvlen)
      (u8vector-set! uv i (string->number (substring str
                                                     (* 2 i)
                                                     (+ (* 2 i) 2))
                                          16)))
    uv))

(define (hash-symbol->class sym)
  (case sym
    ((:sha1)   <sha1>)
    ((:sha256) <sha256>)))

(define (hash-symbol->bytelength sym)
  (case sym
    ((:sha1)   20)
    ((:sha256) 32)))


;; https://tools.ietf.org/html/rfc5869#section-2.2
(define (hkdf-extract hash salt ikm)
  (let1 hmac (make <hmac>
               :key (u8vector->string salt)
               :hasher (hash-symbol->class hash))
    (hmac-update! hmac ikm)
    (string->u8vector (hmac-final! hmac))))

;; https://tools.ietf.org/html/rfc5869#section-2.3
(define (hkdf-expand hash prk info l)
  (let ((hasher  (hash-symbol->class hash))
        (hashlen (hash-symbol->bytelength hash))
        (prk-str (u8vector->string prk))
        (okm     (make-u8vector l)))
    (let loop ((n 1)
               (T ""))
      (let1 hmac (make <hmac> :key prk-str :hasher hasher)
        (hmac-update! hmac T)
        (hmac-update! hmac info)
        (hmac-update! hmac (bytevector n))
        (let1 digest (string->u8vector (hmac-final! hmac))
          (if (<= l (* hashlen n))
              (u8vector-copy! okm (* hashlen (- n 1))
                              digest 0 (- l (* hashlen (- n 1))))
              (begin
                (u8vector-copy! okm (* hashlen (- n 1)) digest 0 hashlen)
                (loop (+ n 1) digest))))))
    okm))

(define (open-quic receiver)
  (let1 sock (make-socket AF_INET SOCK_DGRAM)
    (socket-connect sock (make <sockaddr-in> :host "localhost" :port 4433))
    )
  (receiver "ok\n"))

(define (http3-get url)
  (call/cc (lambda (return)
             (open-quic return))))

(define (main args)
  (display (http3-get "https://localhost:4433/"))
  )
