(use binary.pack)
(use gauche.net)
(use gauche.uvector)
(use srfi-1)
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
    (u8vector-set!  uvec 0 0)
    (u8vector-set!  uvec 1 keylen)
    (u8vector-copy! uvec 2 (string->u8vector key))
    (u8vector-set!  uvec (+ 2 keylen) vallen)
    (u8vector-copy! uvec (+ 2 keylen 1) (string->u8vector val))
    uvec))

(define (make-headers-frame)
  (let1 payload
      (apply append (map u8vector->list
			 (list (make-a-header ":method" "GET")
			       (make-a-header ":scheme" "http")
			       (make-a-header ":authority" "106.186.112.116:80")
			       (make-a-header ":path" "/")
			       )))
    (make-frame *frame-type-headers*
		(+ *flags-end-headers* *flags-end-stream*)
		1 
		(list->u8vector payload))))

(define (make-settings-frame)
  (make-frame *frame-type-settings* 0 0 #u8()))
;;	      #u8(3 0 0 0 100  4 0 1 0 0)))
;;	      #u8(0 0 0 4 0 0 0 100  0 0 0 7 0 1 0 0)))

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

(define (http2-flags->string type flags)
  (format #f "(~a)" flags))

(define (http2 host)
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

  (define (dump-frame-settings payload)
    (while (>= (string-length payload) 5)
      (let1 l (unpack "CN" :from-string #?=payload)
	(case (car l)
	  ((1) (format #t " SETTINGS_HEADER_TABLE_SIZE=~a\n" (cadr l)))
	  (else (format #t " (id=~a,val=~a)\n" (car l) (cadr l)))))
      (set! payload (string-copy payload 5))))

  (define (dump-frame-verbose in)
    (let ((frame (socket-recv in 9999)))
      (format #t "dump: ")
      (dump-hexa (string->u8vector frame))
      (format #t "\n")

      (let1 l (unpack "nCCN" :from-string frame)
	(format #t "  len=~a, type=~a(~a), flags=~a, stream-id=~a\n"
		(first l)
		(http2-type->string (second l)) (second l)
		(http2-flags->string (second l) (third l))
		(fourth l))
	(case (second l)
	  ((4) (dump-frame-settings
		(substring frame 8 (+ 8 (first l)))))
	  (else (print "not verbose"))))))

  (let1 sock (make-client-socket 'inet host 80)
    (socket-send sock http2-magic)
    (send-settings-frame sock)

    ;; 00 18 04 00  00 00 00 00  00 00 00 04  00 00 00 64
    ;; 00 00 00 07  00 00 ff ff  00 00 00 02  00 00 00 00
    ;; len=24 type=4 id=0
    ;; 
    (print "receive settings sent by server:")
    (dump-frame-verbose sock)
    (send-settings-frame-ack sock)

    ;; 00 00 04 01 00 00 00 00
    (print "receive settings sent by server:")
    (dump-frame-verbose sock)

    (send-headers-frame sock)

    (print "receive reply:")
    (while #t
      (dump-frame-verbose sock))
))

(define (usage)
  (display "Usage: http2 <hostname>\n" (current-error-port))
  (exit 1))

(define (parse-url url)
  (rxmatch-let (rxmatch #/^http:\/\/([-A-Za-z\d.]+)(:(\d+))?(\/.*)?/ url)
      (#f host #f port path)
    (values host port path)))

(define (http2-get url)
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
      (http2 (cadr args))
      (usage))
  0)
