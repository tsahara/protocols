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
    ((:sha256) <sha256>)))

(define (hkdf-expand-label hash salt ikm)
  (let1 hmac (make <hmac>
               :key (u8vector->string salt)
               :hasher (hash-symbol->class hash))
    (hmac-update! hmac ikm)
    (string->u8vector (hmac-final! hmac))))


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
