;; TODO:
;; more parameters in SETTINGS frame
;; flow control
;; error code -> string
;; support all frames
;; better error handling
;; API
;; compressed frame

(use binary.io)
(use binary.pack)
(use gauche.collection)
(use gauche.net)
(use gauche.sequence)
(use gauche.uvector)
(use srfi-1)
(use srfi-2)
(use srfi-13)
(use srfi-60)

(load "./http2-hpack.scm")

(define-class <http2-connection> ()
  ((socket  :init-keyword :socket :getter http2-connection-socket)
   (streams :init-value '())
   (next-id :init-value 1)
   (buffer  :init-form (make-u8vector 65536))
   (read-pointer :init-value 0)
   (window-size :init-value 65535)
   ))

(define (make-http2-connection sock)
  (make <http2-connection>
    :socket sock))

(define (http2-connection-setup conn)
  (let ((sock (slot-ref conn 'socket)))
    (http2-connection-write conn "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
    (http2-connection-write conn (make-settings-frame
				  '((SETTINGS_ENABLE_PUSH . 0)
				    (SETTINGS_MAX_CONCURRENT_STREAMS . 1))))
    (http2-connection-recv conn)
    ))

(define (http2-connection-loop conn)
  (http2-connection-write conn (make-settings-frame-ack)))

(define (http2-receive-frame frame)
  (dump-frame-verbose frame))

(define (http2-connection-new-stream conn)
  (let* ((id (http2-connection-next-id conn))
	 (stream (make <http2-stream>
		   :connection conn
		   :id id)))
    (slot-set! conn 'streams
	       (cons (cons id stream)
		     (slot-ref conn 'streams)))
    stream))

(define (http2-connection-get-stream conn id)
  (let1 pair (assq id (slot-ref conn 'streams))
    (and pair (cdr pair))))

(define (http2-connection-next-id conn)
  (rlet1 id (slot-ref conn 'next-id)
    (slot-set! conn 'next-id (+ id 2))))

(define (http2-connection-recv conn)
  (define (u8vector-split vec ptr)
    (let ((head (make-u8vector ptr))
	  (tail (u8vector-copy vec ptr)))
      (u8vector-copy! head 0 vec 0 ptr)
      (values head tail)))

  (let1 n (read-block! (slot-ref conn 'buffer)
		       (socket-input-port (slot-ref conn 'socket))
		       (slot-ref conn 'read-pointer)
		       -1)
    (slot-set! conn 'read-pointer
	       (+ (slot-ref conn 'read-pointer) n))
    (format #t "read ~a bytes, ptr=~a\n" n (slot-ref conn 'read-pointer)))
  
  (while (and-let* (( (>= (slot-ref conn 'read-pointer) 8))    ;; frame header
		    (len (bit-field (get-u16 (slot-ref conn 'buffer) 0) 0 14))
		    ( (>= (slot-ref conn 'read-pointer) (+ 8 len)))
		    (id  (bit-field (get-u32 (slot-ref conn 'buffer) 4) 0 31)))
	   (receive (frame buff)
	       (u8vector-split (slot-ref conn 'buffer) (+ 8 len))
	     (http2-receive-frame frame)
	     (slot-set! conn 'buffer buff)
	     (slot-set! conn 'read-pointer
			(- (slot-ref conn 'read-pointer) (+ 8 len)))))))

(define (http2-connection-write http2 data)
  ;; XXX: write buffering
  (socket-send (slot-ref http2 'socket) data))


(define-class <http2-stream> ()
  ((connection :init-keyword :connection)
   (id         :init-keyword :id :getter http2-stream-id)
   (buffer     :init-form (make-u8vector 65536))
   (read-ptr   :init-value 0     :getter http2-stream-read-ptr)
   ))

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
  (let* ((plen (if (u8vector? payload)
		   (u8vector-length payload)
		   0))
	 (uvec (make-u8vector (+ 8 plen))))
    (set16 uvec 0 plen)
    (u8vector-set! uvec 2 type)
    (u8vector-set! uvec 3 flags)
    (set32 uvec 4 stream-id)
    (if (> plen 0)
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
			       (make-a-header ":path" "/README")
			       )))
    (make-frame *frame-type-headers*
		(+ *flags-end-headers* *flags-end-stream*)
		1
		(list->u8vector payload))))

(define (make-settings-frame params)
  (define (settings-symbol->parameter sym)
    (let1 str (symbol->string sym)
      (+ 1 (find-index (cut string=? str <>)
		       *settings-parameter-type-string*))))
  
  (let1 payload (make-u8vector (* 5 (length params)))
    (for-each-with-index (lambda (i pair)
			   (put-u8!  payload (+ (* 5 i) 0)
				     (settings-symbol->parameter (car pair)))
			   (put-u32! payload (+ (* 5 i) 1) (cdr pair)))
			 params)
    (make-frame *frame-type-settings* 0 0 payload)))

(define (make-settings-frame-ack)
  (make-frame *frame-type-settings* 1 0 #f))

(define (dump-hexa uvec)
  (define maxlen 200)
  (for-each (lambda (byte)
	      (format #t "~2,'0x " byte))
	    (u8vector->list (u8vector-copy uvec 0
					   (min maxlen
						(u8vector-length uvec)))))
  (if (> (u8vector-length uvec) maxlen)
      (format #t "...")))


(define (http2-error-code->string code)
  (if (<= code 12)
      (vector-ref #("NO_ERROR" "PROTOCOL_ERROR" "INTERNAL_ERROR"
		    "FLOW_CONTROL_ERROR" "SETTINGS_TIMEOUT" "STREAM_CLOSED"
		    "FRAME_SIZE_ERROR" "REFUSED_STREAM" "CANCEL"
		    "COMPRESSION_ERROR" "CONNECT_ERROR" "ENHANCE_YOUR_CALM"
		    "INADEQUATE_SECURITY"))
      (format #f "(unknown error code ~a)" code)))

(define (http2-type->string type)
  (if (<= type 10)
      (list-ref '("DATA" "HEADERS" "PRIORITY" "RST_STREAM" "SETTINGS"
		  "PUSH_PROMISE" "PING" "GOAWAY" "WINDOW_UPDATE" "CONTINUATION")
		type)
      "(undefined)"))

(define (http2-flags->string type flags)

  (define (make-string-list flags dict)
    (receive (num str-list)
	(fold2 (lambda (mapping flags str-list)
		 (if (logtest flags (car mapping))
		     (values (- flags (car mapping))
			     (cons (cdr mapping) str-list))
		     (values flags str-list)))
	       flags '() dict)
      (string-join
       (reverse (if (= num 0)
		    str-list
		    (append (list (format #f "0x~x" num)) str-list)))
       ", ")))

  (if (= flags 0)
      "0"
      (case type
	((0) (make-string-list flags '((#x01 . "END_STREAM")
				       (#x02 . "END_SEGMENT")
				       (#x08 . "PAD_LOW")
				       (#x10 . "PAD_HIGH")
				       (#x20 . "COMPRESSED"))))
	((1) (make-string-list flags '((#x01 . "END_STREAM")
				       (#x02 . "END_SEGMENT")
				       (#x04 . "END_HEADERS")
				       (#x08 . "PAD_LOW")
				       (#x10 . "PAD_HIGH")
				       (#x20 . "PRIORITY"))))
	((4) (make-string-list flags '((#x01 . "ACK"))))
	((5) (make-string-list flags '((#x04 . "END_HEADERS")
				       (#x08 . "PAD_LOW")
				       (#x10 . "PAD_HIGH"))))
	((6) (make-string-list flags '((#x01 . "ACK"))))
	((7) (make-string-list flags '((#x04 . "END_HEADERS")
				       (#x08 . "PAD_LOW")
				       (#x10 . "PAD_HIGH"))))
	(else (format #f "(~a)" flags)))))

(define *huffman-tree* (make-huffman-tree))

(define (huffman-decode l next)
  (let ((h   (logbit? 7 (car l)))
	(len (bit-field (car l) 0 7)))
    (if h
	(let loop ((str "")
		   (bytes (cdr l))
		   (bytes-length len)
		   (bits 0)
		   (bits-length 0)
		   (node *huffman-tree*))
	  #;(format #t "(loop (~a ...) 0x~x ~a 0x~x ~a ~a)\n"
		  str (car bytes) bytes-length
		  bits bits-length #f)
	  (if (= bits-length 0)
	      (if (= bytes-length 0)
		  (next str bytes)
		  (loop str (cdr bytes) (- bytes-length 1)
			(car bytes) 8 node))
	      (let1 child (if (logbit? (- bits-length 1) bits)
			      (cdr node)
			      (car node))
		(if (pair? child)
		    (loop str bytes bytes-length bits
			  (- bits-length 1) child)
		    (loop (string-append str (string (integer->char child)))
			  bytes bytes-length bits (- bits-length 1)
			  *huffman-tree*)))))
	(next (list->string (take l len))
	      (drop l len)))))

(define (dump-frame-headers len type flags stream-id payload)
  (define (decode-variable-length-integer l prefix-length)
    (define (mask x) (bit-field x 0 prefix-length))
    (if (< (mask (car l)) (mask 255))
	(values (mask (car l)) (cdr l))
	(let loop ((l (cdr l))
		   (i (mask 255))
		   (m 0))
	  (let1 next-i (+ i (* (logand (car l) 127) (expt 2 m)))
	    (if (logbit? 7 (car l))
		(loop (cdr l) next-i (+ m 7))
		(values next-i (cdr l)))))))

  (define (decode-string-literal l)
    (receive (len str-l)
	(decode-variable-length-integer l 7)
      (if (logbit? 7 (car l))
	  (error "huffman...")
	  (values (list->string (map integer->char (take (cdr l) len)))
		  (drop (cdr l) len)))))
    
  (define (decode-header emit table l)
    (if (pair? l)
	(let1 byte (car l)
	  (cond
	   ;; Indexed Header Field
	   ((logbit? 7 byte) 
	    (begin
	      ;; first entry in static table is indexed 1
	      (let1 pair (list-ref table (- (bit-field byte 0 7) 1))
		(emit (car pair) (cadr pair))
		(decode-header emit (cons pair table) (cdr l)))))
	   
	   ;; Literal Header Field with Incremental Indexing
	   ((logbit? 6 byte) 
	    (let* ((index (bit-field byte 0 6))
		   (entry (list-ref table (- index 1))))
	      (huffman-decode (cdr l) (lambda (str l)
					(emit (car entry) str)
					(decode-header emit
						       (cons entry table)
						       l)))))
	   ;; Encoding Context Update
	   ((logbit? 5 byte)
	    (errorf "Encoding Context Update notyet"))

	   ;; Literal Header Field never Indexed
	   ((logbit? 4 byte)
	    (errorf "notyet header type: Literal Header Field never Indexed"))

	   ;; Literal Header Field without Indexing
	   (else
	    (receive (idx value-l)
		(decode-variable-length-integer l 4)
	      (receive (str next-l)
		  (decode-string-literal value-l)
		(emit (car (list-ref table (- idx 1))) str)
		(decode-header emit table next-l))))))))
    
  (decode-header (lambda (name value)
		   (format #t "  ~a: ~a\n" name value))
		 (list-copy *static-table*)
		 (u8vector->list (string->u8vector payload)))
  )

(define (dump-priority-frame len type flags stream-id payload)
  (format #t "  Exclusive=~a, stream-dependency=~a weight=~a\n"
	  (if (logbit? 7 (get-u8 payload 0)) 1 0)
	  (bit-field (get-u32 payload 0) 0 32)
	  (get-u8 payload 4)))

(define (dump-rst-stream-frame len type flags stream-id payload)
  (format #t "  error-code=~a (~a)\n"
	  (get-u32 payload 0)
	  (http2-error-code->string (get-u32 payload 0))))

(define *settings-parameter-type-string* #("SETTINGS_HEADER_TABLE_SIZE"
					   "SETTINGS_ENABLE_PUSH"
					   "SETTINGS_MAX_CONCURRENT_STREAMS"
					   "SETTINGS_INITIAL_WINDOW_SIZE"
					   "SETTINGS_COMPRESS_DATA"))

(define (dump-frame-settings payload)
  (while (>= (string-length payload) 5)
    (let1 l (unpack "CN" :from-string payload)
      (if (< 0 (car l) (+ (vector-length *settings-parameter-type-string*) 2))
	  (format #t "  ~a=~a\n"
		  (vector-ref *settings-parameter-type-string* (- (car l) 1))
		  (cadr l))
	  (format #t "  (id=~a, val=~a)\n" (car l) (cadr l))))
    (set! payload (string-copy payload 5))))

(define (dump-push-promise-frame len type flags stream-id payload)
  (format #t "  r=~a promised-stream-id=~a\n"
	  (bit-field (get-u32 payload 0) 31 32)
	  (bit-field (get-u32 payload 0) 0 31)
	  ;; XXX: headers
	  ))

(define (dump-ping-frame len type flags stream-id payload)
  (format #t "  ~a\n"
	  (string-join (map (cut format #f "~2,'0x" <>)
			    paylaod)
		       " ")))

(define (dump-goaway-frame len type flags stream-id payload)
  (format #t "  r=~a last-stream-id=~a error-code=~a additional-debug-data=~a\n"
	  (bit-field (get-u32 payload 0) 31 32)
	  (bit-field (get-u32 payload 0) 0 31)
	  (get-u32 payload 4)
	  (u8vector->string (u8vector-copy payload 8))))
  
(define (dump-window-update-frame len type flags stream-id payload)
  (format #t "  r=~a window-size-increment=~a\n"
	  (bit-field (get-u32 payload 0) 31 32)
	  (bit-field (get-u32 payload 0) 0 31)))

(define (dump-continuation-frame len type flags stream-id payload)
  )

(define (dump-frame-verbose frame)
  (format #t "dump: ")
  (dump-hexa frame)
  (format #t "\n")
  
  (let ((len       (bit-field (get-u16 frame 0) 0 14))
	(type      (get-u8 frame 2))
	(flags     (get-u8 frame 3))
	(stream-id (bit-field (get-u32 frame 4) 0 31)))
    (format #t "  len=~a, type=~a(~a), flags=~a, stream-id=~a\n"
	    len
	    (http2-type->string type) type
	    (http2-flags->string type flags)
	    stream-id)
    (case type
      ((1) (dump-frame-headers  len type flags stream-id
				(u8vector->string (u8vector-copy frame 8))))
      ((2) (dump-priority-frame len type flags stream-id
				(u8vector->string (u8vector-copy frame 8))))
      ((3) (dump-rst-stream-frame len type flags stream-id
				  (u8vector->string (u8vector-copy frame 8))))
      ((4) (dump-frame-settings (u8vector->string (u8vector-copy frame 8))))
      ((5) (dump-push-promise-frame len type flags stream-id
				(u8vector->string (u8vector-copy frame 8))))
      ((6) (dump-ping-frame len type flags stream-id
				(u8vector->string (u8vector-copy frame 8))))
      ((7) (dump-goaway-frame len type flags stream-id
				(u8vector->string (u8vector-copy frame 8))))
      ((8) (dump-window-update-frame len type flags stream-id
				(u8vector->string (u8vector-copy frame 8))))
      (else (print "  (XXX: not yet)")))))

(define (http2-old host port)
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

  (let* ((sock (make-client-socket 'inet host port))
	 (conn (make-http2-connection sock)))
    (http2-send-prism-sequence sock)
    (send-settings-frame sock)
    
    ;; receive server settings
    (print "receive settings sent by server:")
    ;(dump-frame-verbose sock)
    (send-settings-frame-ack sock)
    
    (print "receive settings ack:")
    ;(dump-frame-verbose sock)

    (let1 stream (http2-connection-new-stream conn)
      (send-headers-frame sock)

      (while #t
	(http2-connection-recv conn)))
    ))

(define (http2-get url)
  (receive (host port path)
      (parse-url url)
    (let1 http2 (make-http2-connection (make-client-socket 'inet host port))
      (http2-connection-setup http2)
      )))

(define (usage)
  (display "Usage: http2 <url>\n")
  (exit 0))

(define (parse-url url)
  (rxmatch-let (rxmatch #/^http:\/\/([-A-Za-z\d.]+)(:(\d+))?(\/.*)?/ url)
      (#f host #f port path)
    (values host port path)))

(define (http2-get-old url)
  (receive (host port path) (parse-url url)
    (http2-old host port)))

(define (main args)
  (default-endian 'big-endian)
  (if (= (length args) 2)
      (http2-get (cadr args))
      (usage))
  0)
