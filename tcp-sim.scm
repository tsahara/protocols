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
(define *events: (make-binary-heap :key car))

(define (event-add time name . args)

  )



(define (send-syn from to)

  )


(send-syn client server)
