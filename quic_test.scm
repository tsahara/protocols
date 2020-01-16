(use gauche.test)

(test-start "quic test")
(load "./quic.scm")

(define (h2b . str-list)
  (hexadecimal->bytevector (apply string-append str-list)))

(test-section "HKDF")

;; Test Case 1
(let ((IKM  "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
      (salt "000102030405060708090a0b0c")
      (info "f0f1f2f3f4f5f6f7f8f9")
      (L    42)
      (PRK "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
      (OKM (string-append "3cb25f25faacd57a90434f64d0362f2a"
                          "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                          "34007208d5b887185865")))
  (test* "Test Case 1: PRK"
         (hexadecimal->bytevector PRK)
         (hkdf-extract :sha256
                       (hexadecimal->bytevector salt)
                       (hexadecimal->bytevector IKM)))

  (test* "Test Case 1: OKM"
         (hexadecimal->bytevector OKM)
         (hkdf-expand :sha256
                      (hexadecimal->bytevector PRK)
                      (hexadecimal->bytevector info)
                      L))
  )

;; Test Case 2
(let ((hash :sha256)
      (IKM (string-append "000102030405060708090a0b0c0d0e0f"
                          "101112131415161718191a1b1c1d1e1f"
                          "202122232425262728292a2b2c2d2e2f"
                          "303132333435363738393a3b3c3d3e3f"
                          "404142434445464748494a4b4c4d4e4f"))
      (salt (string-append "606162636465666768696a6b6c6d6e6f"
                           "707172737475767778797a7b7c7d7e7f"
                           "808182838485868788898a8b8c8d8e8f"
                           "909192939495969798999a9b9c9d9e9f"
                           "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"))
      (info (string-append "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
                           "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
                           "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
                           "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
                           "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"))
      (L 82)
      (PRK (string-append "06a6b88c5853361a06104c9ceb35b45c"
                          "ef760014904671014a193f40c15fc244"))
      (OKM (string-append "b11e398dc80327a1c8e7f78c596a4934"
                          "4f012eda2d4efad8a050cc4c19afa97c"
                          "59045a99cac7827271cb41c65e590e09"
                          "da3275600c2f09b8367793a9aca3db71"
                          "cc30c58179ec3e87c14c01d5c1f3434f"
                          "1d87")))
  (test* "Test Case 2: PRK"
         (hexadecimal->bytevector PRK)
         (hkdf-extract hash
                       (hexadecimal->bytevector salt)
                       (hexadecimal->bytevector IKM)))
  (test* "Test Case 2: OKM"
         (hexadecimal->bytevector OKM)
         (hkdf-expand hash
                      (hexadecimal->bytevector PRK)
                      (hexadecimal->bytevector info)
                      L))
  )

(let ((hash :sha1)
      (IKM (string-append "0b0b0b0b0b0b0b0b0b0b0b"))
      (salt (string-append "000102030405060708090a0b0c"))
      (info (string-append "f0f1f2f3f4f5f6f7f8f9"))
      (L 42)
      (PRK (string-append "9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243"))
      (OKM (string-append "085a01ea1b10f36933068b56efa5ad81"
                          "a4f14b822f5b091568a9cdd4f155fda2"
                          "c22e422478d305f3f896")))
  (test* "Test Case 3: PRK"
         (hexadecimal->bytevector PRK)
         (hkdf-extract hash
                       (hexadecimal->bytevector salt)
                       (hexadecimal->bytevector IKM)))
  (test* "Test Case 3: OKM"
         (hexadecimal->bytevector OKM)
         (hkdf-expand hash
                      (hexadecimal->bytevector PRK)
                      (hexadecimal->bytevector info)
                      L)))


(test-section "HKDF-Expand-Label")

(let ((initial_salt (h2b "c3eef712c72ebb5a11a7d2432bb46365bef9f502"))
      (initial_secret (h2b "524e374c6da8cf8b496f4bcb69678350"
                           "7aafee6198b202b4bc823ebf7514a423"))
      (client_initial_secret (h2b "fda3953aecc040e48b34e27ef87de3a6"
                                  "098ecf0e38b7e032c5c57bcbd5975b84")))
  (test* "A.1. Keys: initial_secret"
         initial_secret
         (hkdf-extract :sha256 initial_salt (h2b "8394c8f03e515708")))

  (test* "A.1. Keys: client_initial_secret"
         client_initial_secret
         (tls-hkdf-expand-label initial_secret
                                "client in"
                                (u8vector)
                                32))
  (test* "A.1. Keys: key"
         (h2b "af7fd7efebd21878ff66811248983694")
         (tls-hkdf-expand-label client_initial_secret
                                "quic key"
                                (u8vector)
                                16))
  (test* "A.1. Keys: iv"
         (h2b "8681359410a70bb9c92f0420")
         (tls-hkdf-expand-label client_initial_secret
                                "quic iv"
                                (u8vector)
                                12))
  (test* "A.1. Keys: hp"
         (h2b "a980b8b4fb7d9fbc13e814c23164253d")
         (tls-hkdf-expand-label client_initial_secret
                                "quic hp"
                                (u8vector)
                                16)))

(test-end :exit-on-failure #t)
