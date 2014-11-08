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

(ntp-timestamp->string '(3600199852 . 658592681))
