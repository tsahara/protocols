(use binary.io)
(use gauche.net)
(use gauche.selector)
(use gauche.uvector)
(use srfi-19)

(define (ntp-timestamp->string timestamp)
  (define (ntp-seconds->year-and-days seconds)
    (receive (year-without-leap-days
	      days-with-leap-days)
	(quotient&remainder (quotient seconds 86400) 365)

      ;; leap years are:
      ;; 1904, 1908, ..., 1996, 2000, 2004, ..., 2096, 2104, ...
      ;;    4,    8, ...,   96,  100,  104, ...,  196,  204, ... (NTP Era)
      (let1 leap-days (quotient (- year-without-leap-days 1) 4)
	(if (< days-with-leap-days leap-days)
	    (values (+ 1900 year-without-leap-days -1)
		    (+ 365 days-with-leap-days (- leap-days)))
	    (values (+ 1900 year-without-leap-days)
		    (- days-with-leap-days leap-days))))))

  (define (leap-year? year)
    (and (= (remainder year 4) 0)
	 (or (not (= (remainder year 100) 0))
	     (= (remainder year 400) 0))))

  (define (month-and-day year days)
    (define days-in-month #(31 28 31 30 31 30 31 31 30 31 30 31))
    (let loop ((days days)
	       (m    0))
      (let1 d (+ (vector-ref days-in-month m)
		 (if (and (leap-year? year) (= m 1)) 1 0))
	(if (< days d)
	    (values (+ m 1) (+ days 1))
	    (loop (- days d) (+ m 1))))))

  (receive (year days)
      (ntp-seconds->year-and-days (car timestamp))
    (receive (month day)
	(month-and-day year days)
      (format #t "~a/~a/~a\n" year month day))))

; (ntp-timestamp->string '(3600199852 . 658592681))

(define (make-ntp-query-message)
  (let1 bytes (make-u8vector 48)
    (put-u8!    bytes  0 (+ (ash 0 6)  ; LI
			    (ash 4 3)  ; VN: version 4
			    3))        ; Mode: client(3)
    (put-u8!    bytes  1 0)            ; Stratum
    (put-u8!    bytes  2 0)            ; Poll
    (put-u8!    bytes  3 0)            ; Precision
    (put-u32be! bytes  4 0)            ; Root Delay
    (put-u32be! bytes  8 0)            ; Root Dispersion
    (put-u32be! bytes 12 0)            ; Reference ID
    (put-u64be! bytes 16 0)            ; Reference Timestamp
    (put-u64be! bytes 24 0)            ; Origin Timestamp
    (put-u64be! bytes 32 0)            ; Receive Timestamp
    (put-u64be! bytes 40 0)            ; Transmit Timestamp
    bytes))

(define (print-ntp-packet name addr uv)
  (define (refid->printable)
    (let1 refid (u8vector->list uv 12 16)
      (if (every (lambda (byte)
		   (let1 ch (integer->char byte)
		     (or (char-alphabetic? ch) (char-numeric? ch))))
		 refid)
	  (apply string (map integer->char refid))
	  (string-join (map number->string refid)
		       "."))))
  (define (servertime)
    (date->string
     (time-utc->date (make-time time-utc 0
				(- (get-u32be uv 40)
				   (* 70 365 86400)
				   (* 17 86400)))
		     (* 9 3600))
     "~4"))

  (let1 l `((localtime . ,(date->string (current-date) "~4"))
	    (name      . ,name)
	    (address   . ,(sockaddr-name addr)))
    (print (append l (if uv
			 `((leap         . ,(bit-field (get-u8 uv 0) 6 8))
			   (stratum      . ,(get-u8 uv 1))
			   (reference-id . ,(refid->printable))
			   (servertime   . ,(servertime)))
			 '((error . timeout)))))))

(define (wait-for-read port-or-fd second)
  (let1 selector (make <selector>)
    (call/cc (lambda (return)
	       (selector-add! selector port-or-fd (lambda x
						    (return #t))
			      (list'r))
	       (selector-select selector (list second 0))
	       (return #f)))))

(define (ntp-query host)
  (define (primary-address host port)
    (car
     (sort (make-sockaddrs host port 'udp)
	   (lambda (x y)
	     (let ((xf (sockaddr-family x))
		   (yf (sockaddr-family y)))
	       (or (and (eq? xf 'inet) (eq? yf 'inet6))
		   (and (eq? xf yf)
			(< (sockaddr-addr x)
			   (sockaddr-addr y)))))))))

  (let1 addr (primary-address host 123)
    (let ((sock (make-socket (if (eq? (sockaddr-family addr) 'inet)
				 AF_INET
				 AF_INET6)
			     SOCK_DGRAM))
	  (recvbuf (make-u8vector 2048)))
      (socket-connect sock addr)
      (socket-send sock (make-ntp-query-message))
      (print-ntp-packet host addr
			(if (wait-for-read (socket-fd sock) 3)
			    (let1 len (socket-recv! sock recvbuf)
			      (u8vector-copy recvbuf 0 len))
			    #f)))))

(define (main args)
  (ntp-query (cadr args)))
