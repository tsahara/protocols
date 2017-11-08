;(use femto.dns)
(use gauche.uvector)
(use rfc.base64)

(base64-decode-string "AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0OgcCjF")

"49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5"

(define (calc-keytag uv)
  (let ((len (u8vector-length uv))
	(sum 0))
    (dotimes (i (quotient len 2))
      (set! sum (+ sum
		   (* 256 (u8vector-ref uv (* i 2)))
		   (u8vector-ref uv (+ (* i 2) 1)))))
    (remainder (+ (quotient sum #x10000)
		  sum)
	       #x10000)))

(let ((uv (string->u8vector (base64-decode-string "AwEAAcRIZfxskdElMKgjwvWQO2bQe7EGAvX6zgIaqmbsaMqmMrIpd1+b P7nyULLuL8jWnKAqcaVfal2yJD50gg5zFl5yW/F9dKNXXEFI7VEcGrPy G6/OrA9RBU8pGWm0qxpsNm5UIgTU5IX7pb/0rBj67c/R7qln8sjH1yls r4f1Y3R6p/druiEalKasEjGKA9L2w9jzUQusWxM7fQx/T8c/3x3bsjve D1dleQ6MJaCx4bpPXYZpqXmSvGn+T2v5350cBVAFqVKhGbjxEyXAweem 8cTU4L1p+DV7Ua11a1tMf0Tlu8pkpLwh7NQIggIEhJwEhPeXE3E4C6Q2 /PFENcoFERc="))))
  (let* ((elen   (u8vector-ref uv 0))
	 (uv-exp (u8vector 1 (+ 1 elen)))
	 (uv-mod (u8vector (+ 1 elen)))
	 (raw    (u8vector-append (u8vector 1 0 3 8) uv)))
    #?=(calc-keytag raw)))


;; .			77174	IN	DNSKEY	256 3 8 AwEAAcRIZfxskdElMKgjwvWQO2bQe7EGAvX6zgIaqmbsaMqmMrIpd1+b P7nyULLuL8jWnKAqcaVfal2yJD50gg5zFl5yW/F9dKNXXEFI7VEcGrPy G6/OrA9RBU8pGWm0qxpsNm5UIgTU5IX7pb/0rBj67c/R7qln8sjH1yls r4f1Y3R6p/druiEalKasEjGKA9L2w9jzUQusWxM7fQx/T8c/3x3bsjve D1dleQ6MJaCx4bpPXYZpqXmSvGn+T2v5350cBVAFqVKhGbjxEyXAweem 8cTU4L1p+DV7Ua11a1tMf0Tlu8pkpLwh7NQIggIEhJwEhPeXE3E4C6Q2 /PFENcoFERc=


;; jp.			86400	IN	RRSIG	DS
;; alg=8=RSASHA256 1 86400 expire=20171119210000 inception=20171106200000
;; keytag=46809
;; signer=.
;; ZYHOOzZo7aejB5ObtL7sB8h1+JXZ+68S7LJsirEW9IfYiJepMrXKfEFw 0dTb9mT3e0tWUMmjfgX6Bf462NfCPpmPrzPcXofb3nd/ZLFsFNp9nK7R BY3itYTAf0XyQxuA2c3UAfA3tgjnLEitEF25UdSQreA88cyChrNweSs2 sdZMThUeQ8gMLjYYgPXKn8jChVIhUL3t9kzTtOuSb/hiMzpYM6uVrcFw tr+jFr184GyDGMpzC5TKDaA/LVlvcZ2X3MJ5+6ty5i6znXkPeiTondl6 HSqEbS7rthKgOKH3EC7P0rG/dMK6Ted4CqPBv/ar8nwdv+kv75hVEm2e gnAURw==

;;jp.			47880	IN	DS	31714 8 1 B6CB06C153CB0C73BCEBA9914BAF16F26A9B931E
;;jp.			47880	IN	DS	31714 8 2 612693CC16178D788F6A2733E4F01647B027FAE678CB3BF92EC4143F 67A559D8
