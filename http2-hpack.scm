(define (make-huffman-tree)
  (define (addsym node byte bits width)
    (if (= width 1)
	(if (logbit? 0 bits)
	    (set-cdr! node byte)
	    (set-car! node byte))
	(let1 child (if (logbit? (- width 1) bits)
			(cdr node)
			(car node))
	  (unless child
	    (set! child (cons #f #f))
	    (if (logbit? (- width 1) bits)
		(set-cdr! node child)
		(set-car! node child)))
	  (addsym child byte bits (- width 1)))))

  (let1 root (cons #f #f)
    (for-each (lambda (l)
		(addsym root (car l) (cadr l) (caddr l)))
	      *huffman-table-in-spec*)
    root))

(define *huffman-table-in-spec*
  '((  0 #x3ffffba 26)
    (  1 #x3ffffbb 26)
    (  2 #x3ffffbc 26)
    (  3 #x3ffffbd 26)
    (  4 #x3ffffbe 26)
    (  5 #x3ffffbf 26)
    (  6 #x3ffffc0 26)
    (  7 #x3ffffc1 26)
    (  8 #x3ffffc2 26)
    (  9 #x3ffffc3 26)
    ( 10 #x3ffffc4 26)
    ( 11 #x3ffffc5 26)
    ( 12 #x3ffffc6 26)
    ( 13 #x3ffffc7 26)
    ( 14 #x3ffffc8 26)
    ( 15 #x3ffffc9 26)
    ( 16 #x3ffffca 26)
    ( 17 #x3ffffcb 26)
    ( 18 #x3ffffcc 26)
    ( 19 #x3ffffcd 26)
    ( 20 #x3ffffce 26)
    ( 21 #x3ffffcf 26)
    ( 22 #x3ffffd0 26)
    ( 23 #x3ffffd1 26)
    ( 24 #x3ffffd2 26)
    ( 25 #x3ffffd3 26)
    ( 26 #x3ffffd4 26)
    ( 27 #x3ffffd5 26)
    ( 28 #x3ffffd6 26)
    ( 29 #x3ffffd7 26)
    ( 30 #x3ffffd8 26)
    ( 31 #x3ffffd9 26)
    ( 32       #x6  5)
    ( 33    #x1ffc 13)
    ( 34     #x1f0  9)
    ( 35    #x3ffc 14)
    ( 36    #x7ffc 15)
    ( 37      #x1e  6)
    ( 38      #x64  7)
    ( 39    #x1ffd 13)
    ( 40     #x3fa 10)
    ( 41     #x1f1  9)
    ( 42     #x3fb 10)
    ( 43     #x3fc 10)
    ( 44      #x65  7)
    ( 45      #x66  7)
    ( 46      #x1f  6)
    ( 47       #x7  5)
    ( 48       #x0  4)
    ( 49       #x1  4)
    ( 50       #x2  4)
    ( 51       #x8  5)
    ( 52      #x20  6)
    ( 53      #x21  6)
    ( 54      #x22  6)
    ( 55      #x23  6)
    ( 56      #x24  6)
    ( 57      #x25  6)
    ( 58      #x26  6)
    ( 59      #xec  8)
    ( 60   #x1fffc 17)
    ( 61      #x27  6)
    ( 62    #x7ffd 15)
    ( 63     #x3fd 10)
    ( 64    #x7ffe 15)
    ( 65      #x67  7)
    ( 66      #xed  8)
    ( 67      #xee  8)
    ( 68      #x68  7)
    ( 69      #xef  8)
    ( 70      #x69  7)
    ( 71      #x6a  7)
    ( 72     #x1f2  9)
    ( 73      #xf0  8)
    ( 74     #x1f3  9)
    ( 75     #x1f4  9)
    ( 76     #x1f5  9)
    ( 77      #x6b  7)
    ( 78      #x6c  7)
    ( 79      #xf1  8)
    ( 80      #xf2  8)
    ( 81     #x1f6  9)
    ( 82     #x1f7  9)
    ( 83      #x6d  7)
    ( 84      #x28  6)
    ( 85      #xf3  8)
    ( 86     #x1f8  9)
    ( 87     #x1f9  9)
    ( 88      #xf4  8)
    ( 89     #x1fa  9)
    ( 90     #x1fb  9)
    ( 91     #x7fc 11)
    ( 92 #x3ffffda 26)
    ( 93     #x7fd 11)
    ( 94    #x3ffd 14)
    ( 95      #x6e  7)
    ( 96   #x3fffe 18)
    ( 97       #x9  5)
    ( 98      #x6f  7)
    ( 99       #xa  5)
    (100      #x29  6)
    (101       #xb  5)
    (102      #x70  7)
    (103      #x2a  6)
    (104      #x2b  6)
    (105       #xc  5)
    (106      #xf5  8)
    (107      #xf6  8)
    (108      #x2c  6)
    (109      #x2d  6)
    (110      #x2e  6)
    (111       #xd  5)
    (112      #x2f  6)
    (113     #x1fc  9)
    (114      #x30  6)
    (115      #x31  6)
    (116       #xe  5)
    (117      #x71  7)
    (118      #x72  7)
    (119      #x73  7)
    (120      #x74  7)
    (121      #x75  7)
    (122      #xf7  8)
    (123   #x1fffd 17)
    (124     #xffc 12)
    (125   #x1fffe 17)
    (126     #xffd 12)
    (127 #x3ffffdb 26)
    (128 #x3ffffdc 26)
    (129 #x3ffffdd 26)
    (130 #x3ffffde 26)
    (131 #x3ffffdf 26)
    (132 #x3ffffe0 26)
    (133 #x3ffffe1 26)
    (134 #x3ffffe2 26)
    (135 #x3ffffe3 26)
    (136 #x3ffffe4 26)
    (137 #x3ffffe5 26)
    (138 #x3ffffe6 26)
    (139 #x3ffffe7 26)
    (140 #x3ffffe8 26)
    (141 #x3ffffe9 26)
    (142 #x3ffffea 26)
    (143 #x3ffffeb 26)
    (144 #x3ffffec 26)
    (145 #x3ffffed 26)
    (146 #x3ffffee 26)
    (147 #x3ffffef 26)
    (148 #x3fffff0 26)
    (149 #x3fffff1 26)
    (150 #x3fffff2 26)
    (151 #x3fffff3 26)
    (152 #x3fffff4 26)
    (153 #x3fffff5 26)
    (154 #x3fffff6 26)
    (155 #x3fffff7 26)
    (156 #x3fffff8 26)
    (157 #x3fffff9 26)
    (158 #x3fffffa 26)
    (159 #x3fffffb 26)
    (160 #x3fffffc 26)
    (161 #x3fffffd 26)
    (162 #x3fffffe 26)
    (163 #x3ffffff 26)
    (164 #x1ffff80 25)
    (165 #x1ffff81 25)
    (166 #x1ffff82 25)
    (167 #x1ffff83 25)
    (168 #x1ffff84 25)
    (169 #x1ffff85 25)
    (170 #x1ffff86 25)
    (171 #x1ffff87 25)
    (172 #x1ffff88 25)
    (173 #x1ffff89 25)
    (174 #x1ffff8a 25)
    (175 #x1ffff8b 25)
    (176 #x1ffff8c 25)
    (177 #x1ffff8d 25)
    (178 #x1ffff8e 25)
    (179 #x1ffff8f 25)
    (180 #x1ffff90 25)
    (181 #x1ffff91 25)
    (182 #x1ffff92 25)
    (183 #x1ffff93 25)
    (184 #x1ffff94 25)
    (185 #x1ffff95 25)
    (186 #x1ffff96 25)
    (187 #x1ffff97 25)
    (188 #x1ffff98 25)
    (189 #x1ffff99 25)
    (190 #x1ffff9a 25)
    (191 #x1ffff9b 25)
    (192 #x1ffff9c 25)
    (193 #x1ffff9d 25)
    (194 #x1ffff9e 25)
    (195 #x1ffff9f 25)
    (196 #x1ffffa0 25)
    (197 #x1ffffa1 25)
    (198 #x1ffffa2 25)
    (199 #x1ffffa3 25)
    (200 #x1ffffa4 25)
    (201 #x1ffffa5 25)
    (202 #x1ffffa6 25)
    (203 #x1ffffa7 25)
    (204 #x1ffffa8 25)
    (205 #x1ffffa9 25)
    (206 #x1ffffaa 25)
    (207 #x1ffffab 25)
    (208 #x1ffffac 25)
    (209 #x1ffffad 25)
    (210 #x1ffffae 25)
    (211 #x1ffffaf 25)
    (212 #x1ffffb0 25)
    (213 #x1ffffb1 25)
    (214 #x1ffffb2 25)
    (215 #x1ffffb3 25)
    (216 #x1ffffb4 25)
    (217 #x1ffffb5 25)
    (218 #x1ffffb6 25)
    (219 #x1ffffb7 25)
    (220 #x1ffffb8 25)
    (221 #x1ffffb9 25)
    (222 #x1ffffba 25)
    (223 #x1ffffbb 25)
    (224 #x1ffffbc 25)
    (225 #x1ffffbd 25)
    (226 #x1ffffbe 25)
    (227 #x1ffffbf 25)
    (228 #x1ffffc0 25)
    (229 #x1ffffc1 25)
    (230 #x1ffffc2 25)
    (231 #x1ffffc3 25)
    (232 #x1ffffc4 25)
    (233 #x1ffffc5 25)
    (234 #x1ffffc6 25)
    (235 #x1ffffc7 25)
    (236 #x1ffffc8 25)
    (237 #x1ffffc9 25)
    (238 #x1ffffca 25)
    (239 #x1ffffcb 25)
    (240 #x1ffffcc 25)
    (241 #x1ffffcd 25)
    (242 #x1ffffce 25)
    (243 #x1ffffcf 25)
    (244 #x1ffffd0 25)
    (245 #x1ffffd1 25)
    (246 #x1ffffd2 25)
    (247 #x1ffffd3 25)
    (248 #x1ffffd4 25)
    (249 #x1ffffd5 25)
    (250 #x1ffffd6 25)
    (251 #x1ffffd7 25)
    (252 #x1ffffd8 25)
    (253 #x1ffffd9 25)
    (254 #x1ffffda 25)
    (255 #x1ffffdb 25)
    (256 #x1ffffdc 25)))

(define *static-table*
  '((:authority                  )
    (:method                     GET)
    (:method                     POST)
    (:path                       /)
    (:path                       /index.html)
    (:scheme                     http)
    (:scheme                     https)
    (:status                     200)
    (:status                     204)
    (:status                     206)
    (:status                     304)
    (:status                     400)
    (:status                     404)
    (:status                     500)
    (accept-charset              )
    (accept-encoding             )
    (accept-language             )
    (accept-ranges               )
    (accept                      )
    (access-control-allow-origin )
    (age                         )
    (allow                       )
    (authorization               )
    (cache-control               )
    (content-disposition         )
    (content-encoding            )
    (content-language            )
    (content-length              )
    (content-location            )
    (content-range               )
    (content-type                )
    (cookie                      )
    (date                        )
    (etag                        )
    (expect                      )
    (expires                     )
    (from                        )
    (host                        )
    (if-match                    )
    (if-modified-since           )
    (if-none-match               )
    (if-range                    )
    (if-unmodified-since         )
    (last-modified               )
    (link                        )
    (location                    )
    (max-forwards                )
    (proxy-authenticate          )
    (proxy-authorization         )
    (range                       )
    (referer                     )
    (refresh                     )
    (retry-after                 )
    (server                      )
    (set-cookie                  )
    (strict-transport-security   )
    (transfer-encoding           )
    (user-agent                  )
    (vary                        )
    (via                         )
    (www-authenticate            )))
