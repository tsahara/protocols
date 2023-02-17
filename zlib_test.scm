(use gauche.test)

(load "./zlib.scm")

(test-start "zlib")

(test-section "reverse")
(test* "#x12 (8bits) -> #x48" #x48 (reverse-bits #x12 8))
(test* "#xff (5bits) -> #x1f" #x1f (reverse-bits #xff 5))

(test-section "inflate")
(test* "empty string"
       #u8()
       (zlib-decompress #u8(#x78 #x9c #x03 #x00 #x00 #x00 #x00 #x01)))

(test* "single literal character"
       (string->utf8 "a")
       (zlib-decompress #u8(#x78 #x9c #x4b #x04 #x00 #x00 #x62 #x00 #x62)))

(test* "literal string"
       (string->utf8 "abc")
       (zlib-decompress #u8(#x78 #x9c #x4b #x4c #x4a #x06 #x00
                                 #x02 #x4d #x01 #x27)))

(test* "backward reference"
       (string->utf8 "abcdabcd")
       (zlib-decompress #u8(#x78 #x9c #x4b #x4c #x4a #x4e #x49 #x04 #x62 #x00
                                 #x0d #xd8 #x03 #x15)))

(exit (test-end))
