(use gauche.uvector)
(use rfc.base64)
(use srfi-13)

(load "./asn1.scm")

(define (string->x509 str)
  (set! str (string-scan str "-----BEGIN CERTIFICATE-----" 'after))
  (set! str (string-scan str "-----END CERTIFICATE-----" 'before))
  (decode-x509-der (string->u8vector
		    (base64-decode-string str))))

(define (main args)
  (call-with-input-file (cadr args)
    (compose string->x509 port->string)))
