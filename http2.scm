(use gauche.net)
(use gauche.uvector)
(use srfi-13)

(define http2-magic
  (string->u8vector "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))

(define (set16 uvec offset num)
  (u8vector-set! uvec offset (quotient num 256))
  (u8vector-set! uvec (+ offset 1) (remainder num 256)))

(define (set32 uvec offset num)
  (u8vector-set! uvec offset
		 (quotient num (* 256 256 256)))
  (u8vector-set! uvec (+ offset 1)
		 (remainder (quotient num (* 256 256)) 256))
  (u8vector-set! uvec (+ offset 2)
		 (remainder (quotient num 256) 256))
  (u8vector-set! uvec (+ offset 3) (remainder num 256)))

(define (make-frame type flags stream-id payload)
  (let1 uvec (make-u8vector (+ 8 (u8vector-length payload)))
    (set16 uvec 0 (u8vector-length payload))
    (u8vector-set! uvec 2 type)
    (u8vector-set! uvec 3 flags)
    (set32 uvec 4 stream-id)
    (if (> (u8vector-length payload) 0)
	(u8vector-copy! uvec 8 payload))
    uvec))

(define *frame-type-data*       0)
(define *frame-type-headers*    1)
(define *frame-type-rst-stream* 3)
(define *frame-type-settings*   4)
(define *frame-type-goaway*     7)

(define *flags-ack*          #x1)

(define *flags-end-stream*  #x1)
(define *flags-end-headers*  #x4)


(define (make-a-header key val)
  (let* ((keylen (string-length key))
	 (vallen (string-length val))
	 (uvec (make-u8vector (+ 3 keylen vallen))))
    (u8vector-set!  uvec 0 #x40)
    (u8vector-set!  uvec 1 keylen)
    (u8vector-copy! uvec 2 (string->u8vector key))
    (u8vector-set!  uvec (+ 2 keylen) vallen)
    (u8vector-copy! uvec (+ 2 keylen 1) (string->u8vector val))
    uvec))

(define (make-headers-frame)
  (let1 payload
      (apply append (map u8vector->list
			 (list #u8(#x80 #x80)
			       (make-a-header ":method" "GET")
			       (make-a-header ":scheme" "http")
			       (make-a-header ":authority" "106.186.112.116:80")
			       (make-a-header ":path" "/")
			       )))
    (make-frame *frame-type-headers*
		(+ *flags-end-headers* *flags-end-stream*)
		1 
		(list->u8vector payload))))

(define (make-settings-frame)
  (make-frame *frame-type-settings* 0 0
;;	      #u8(3 0 0 0 100  4 0 1 0 0)))
	      #u8(0 0 0 4 0 0 0 100  0 0 0 7 0 1 0 0)))

(define (dump-hexa uvec)
  (for-each (lambda (byte)
	      (format #t "~2,'0x " byte))
	    (u8vector->list uvec)))
;; (dump-hexa (make-headers-frame))

(define (http2-type->string type)
  (if (<= type 10)
      (list-ref '("DATA" "HEADERS" "PRIORITY" "RST_STREAM" "SETTINGS"
		  "PUSH_PROMISE" "PING" "GOAWAY" "WINDOW_UPDATE" "CONTINUATION")
		type)
      "(undefined)"))

(define (http2-flags->readable-string type flags)
  (if (<= type 10)
      (list-ref '("DATA" "HEADERS" "PRIORITY" "RST_STREAM" "SETTINGS"
		  "PUSH_PROMISE" "PING" "GOAWAY" "WINDOW_UPDATE" "CONTINUATION")
		type)
      "(undefined)"))

(define (http2)
  (define (send-headers-frame sock)
    (socket-send sock (make-headers-frame)))

  (define (send-settings-frame sock)
    (socket-send sock (make-settings-frame)))

  (define (send-settings-frame-ack sock)
    (socket-send sock
		 (make-frame *frame-type-settings*
			     *flags-ack*
			     0
			     (make-u8vector 0))))

  (define (dump-frame in)
    (format #t "dump: ")
    (let ((frame (string->u8vector (socket-recv in 9999))))
      (dump-hexa frame))
    (format #t "(end)\n")
    )

  (define (dump-frame-verbose in)
    (let ((frame (string->u8vector (socket-recv in 9999))))
      (format #t "dump: ")
      (dump-hexa frame)
      (format #t "\n")

      (let ((len   (+ (* (u8vector-ref frame 1) #x100)
		      (u8vector-ref frame 0)))
	    (type  (u8vector-ref frame 2))
	    (flags (u8vector-ref frame 3)))
	(format #t "  len=~a, type=~a(~a), flags=~a\n"
		len (http2-type->string type) type flags)
	)))

  (let1 sock (make-client-socket 'inet "106.186.112.116" 80)
    (socket-send sock http2-magic)
    (send-settings-frame sock)

    ;; 00 18 04 00  00 00 00 00  00 00 00 04  00 00 00 64
    ;; 00 00 00 07  00 00 ff ff  00 00 00 02  00 00 00 00
    ;; len=24 type=4 id=0
    ;; 
    (print "receive settings sent by server:")
    (dump-frame sock)
    (send-settings-frame-ack sock)

    ;; 00 00 04 01 00 00 00 00
    (print "receive settings sent by server:")
    (dump-frame-verbose sock)

    (send-headers-frame sock)

    (print "receive reply of headers:")

    #;(print (string-take (socket-recv sock 9999) 300))
    (print (socket-recv sock 9999))
))

;; (http2)


(define (usage)
  (display "Usage: swget url\n" (current-error-port))
  (exit 1))

(define (parse-url url)
  (rxmatch-let (rxmatch #/^http:\/\/([-A-Za-z\d.]+)(:(\d+))?(\/.*)?/ url)
      (#f host #f port path)
    (values host port path)))

(define (get url)
  (receive (host port path) (parse-url url)
    (call-with-client-socket
        (make-client-socket 'inet host (string->number (or port "80")))
      (lambda (in out)
        (format out "GET ~a HTTP/1.0\r\n" path)
        (format out "host: ~a\r\n\r\n" host)
        (flush out)
        (copy-port in (current-output-port))))))

(define (main args)
  (if (= (length args) 2)
      (get (cadr args))
      (usage))
  0)
