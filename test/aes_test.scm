(use gauche.test)

;(test-start "aes test")
(load "./aes.scm")

(define (h2b . l)
  (hexadecimal->bytevector (apply string-append l)))

(let ((key   (hexadecimal->bytevector "000102030405060708090a0b0c0d0e0f"))
      (input (hexadecimal->bytevector "00112233445566778899aabbccddeeff"))
      (output (hexadecimal->bytevector "69c4e0d86a7b0430d8cdb78070b4c55a")))
  (test* "aes 128 ecb"
         output
         (aes-encrypt key #f input)))

(let ((key   (h2b "000102030405060708090a0b0c0d0e0f1011121314151617"))
      (input (hexadecimal->bytevector "00112233445566778899aabbccddeeff"))
      (output (hexadecimal->bytevector "dda97ca4864cdfe06eaf70a0ec0d7191")))
  (test* "aes 192 ecb"
         output
         (aes-encrypt key #f input)))

(let ((key   (h2b "000102030405060708090a0b0c0d0e0f"
                  "101112131415161718191a1b1c1d1e1f"))
      (input (hexadecimal->bytevector "00112233445566778899aabbccddeeff"))
      (output (hexadecimal->bytevector "8ea2b7ca516745bfeafc49904b496089")))
  (test* "aes 256 ecb"
         output
         (aes-encrypt key #f input)))

(test-end :exit-on-failure #t)
