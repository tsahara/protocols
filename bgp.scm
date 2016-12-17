(use binary.io)
(use gauche.net)

(define *my-router-id* (list 172 16 0 1))
(define *my-asn*       65001)

(define (make-bgp-client)
  (make-client-socket 'inet "172.16.0.2" 179))

;; max length of the bgp message is 4096 (1st paragraph of 4.)
(define (bgp-read-from-socket sock)
  (let1 buf (make-u8vector 2048)
    (let1 num (socket-recv! sock buf)
      (u8vector-copy buf 0 num))))

(define (make-bgp-message type payload)
  (let1 uv (u8vector-append (make-u8vector 19 #xff) payload)
    (put-u16be! uv 16 (u8vector-length uv))
    (put-u8!    uv 18 type)
    (if (> (u8vector-length uv) 4096) (error "too long!"))
    uv))

(define (make-bgp-open-message)
  (let1 uv (make-u8vector 10)
    (put-u8!    uv 0 4)           ;; Version
    (put-u16be! uv 1 *my-asn*)    ;; My Autonomous System
    (put-u16be! uv 3 32)          ;; Hold Time
    (u8vector-copy! uv 5 (list->u8vector *my-router-id*))  ;; BGP Identifier
    (put-u8!    uv 9 0)           ;; Optional Parameters Length
    (make-bgp-message 1 uv)))

(let ((bgp (make-bgp-client))
	    (buf (make-u8vector 4096)))
	(socket-send bgp (make-bgp-open-message))
	(socket-recv! bgp buf)
	(print buf))
