#!/usr/bin/env gosh

(use gauche.net)
(use gauche.uvector)
(use srfi-19)

(define *content-type-change_cipher_spec* 20)
(define *content-type-alert*              21)
(define *content-type-handshake*          22)
(define *content-type-application-data*   23)

(define (insecure-random-sequence byte-count)
  (iota byte-count))

(define (tls-client-random)
  (append
   (let1 sec (time-second (current-time))
     (map (cut remainder <> 256)
	  (list (quotient sec (* 256 256 256))
		(quotient sec (* 256 256))
		(quotient sec 256)
		sec)))
   (insecure-random-sequence 28)))

(define (tls-client-hello)
  (define (make-client-hello-tls-message handshake)
    (let1 msg-len (length handshake)
      (append (list 22    ; ContetType = handshake
		    3 1)  ; TLS version
	      (list (remainder (quotient msg-len 256) 256)
		    (remainder msg-len 256))
	      handshake)))

  (define (make-client-hello payload)
    (append (let1 payload-len (length payload)
	      (list 1
		    (remainder (quotient payload-len (* 256 256)) 256)
		    (remainder (quotient payload-len 256) 256)
		    (remainder payload-len 256)))
	    payload))

  (list->u8vector
   (make-client-hello-tls-message
    (make-client-hello
     (append (list 3 1)          ; client_version
	     (tls-client-random)
	     (list 0)            ; SessionID length
	     (list 0 4 0 0 0 5)  ; cipher_suites TLS_RSA_WITH_RC4_128_SHA
	     (list 1 0)          ; compression_methods 0
	    )))))

(define (TLSPlaintext ContentType major minor content)
  (list *content-type-handshake* 3 3)
  )

(define (send-client-hello sock)
  (socket-send sock (tls-client-hello)))

(define (read-dump sock)
  #?=(socket-recv sock 1000))

(let1 sock (make-client-socket 'inet "localhost" 4433)
  (send-client-hello sock)
  (read-dump sock))
