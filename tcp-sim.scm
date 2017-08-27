(use data.heap)

(define rtt 0.300)   ;; in seconds

(define-class <tcp> ()
  ())

(define client (make <tcp>))
(define server (make <tcp>))

(define *wallclock* 0)

;;
;; Future Events
;;
(define *events* (make-binary-heap :key car))

(define (event-add time name . args)
  (binary-heap-push! *events* (cons* time name args)))

(define (events-print)
  (let1 h (binary-heap-copy *events*)
    (while (not (binary-heap-empty? h))
      (print (binary-heap-pop-min! h)))))

(define (send-syn from to)
  (event-add rtt :syn '())
  )


(send-syn client server)
(events-print)
