## TODO
 - 単一コネクションで複数streamを動かした時に date: 24906 とヘッダのパーズに
   失敗するのを直す
 - (sys-sleep 1) を有効にするとまた違うエラーが出る

## -11 への追随
 - stream prioritization
 - "h2c" の追加
 - PUSH_PROMISE への padding の追加
 - ALTSVC

## 未整理
 - Connection
   - Connection の中に stream がある
   - 複数の stream を持つ
   - 並列で動ける(interleave)
   - Server - Client 間の Connection 数は原則1本 (SHOULD)

 - Stream
   - 複数あるので番号付けされる
   - 0 番は Connection の制御用
   - stream は複数同時に動く : stream の中に request/response とかが通る

 - Frame
   - バイナリ
   - 固定長の 64bit ヘッダ + 可変長ペイロード
   - reserved  (2bit)
   - length (14bit)
   - type (8bit)
     - `WINDOW_UPDATE` とかは -10 でリナンバされたっぽい
   - flags (8bit)
     - `END_STREAM`, `END_HEADER` フラグ等
   - reserved (1bit)
   - stream identifier (31bit)
     - クライアントとサーバは偶奇で分かれる
   - length が 14bit なので 16383 bytes まで
   - 

 - HTTP メッセージ
   - = HEADERS frame (2つ) + DATA frame
   - Request / Response / Server-Push の 3つになった

 - Conenction Establishment
   - やり方は 4通り
     1. TLS ALPN : TLS の ClientHello でネゴる
	 2. TLS NPN : obsolete だがまだ残ってる
	 3. Upgrade ヘッダ : HTTP 1.1 からのアップグレード
	 4. ネゴらずいきなり HTTP2 フレームを送る

   - まず Connection Headr (24octets) を送り、次にクライアントから SETTINGS を送り、
     サーバから SETTINGS を受け取る
	 - ヘッダ圧縮その他をネゴる

 - Frame Types
   - DATA FRAME
     - padding は -10 から入った
   - HEADER FRAME
     - Header Block Fragment という形式で入る
	 - frame header の `END_HEADER` フラグを使う
   - SETTINGS FRAME
     - リクエストと ACK がある
	 - `SETTINGS_HEADER_TABLE_SIZE` : ヘッダ圧縮に使う
	 - `SETTINGS_ENABLE_PUSH`
	 - `SETTINGS_MAX_CONCURRENT_STREAMS`
	 - `SETTINGS_INITIAL_WINDOW_SIZE`
   - GOAWAY FRAME
     - TCP でいうところの FIN

 - Request
   - Request-Line はメソッドで分かれた
     - :method :scheme :authority :path
	 - これだけ送ればとりあえず良い。HTTP 1.1 の Host: みたいな必須ヘッダは他は無い。
   - :auhtority は www.exmaple.jp:80 の部分
 	 - Status も :status で数値のみ
     - Stream ID は昇順にふる
	   - Push 用の ID は事前に予約できたりする
	 - Stream は 7つの状態を持つ状態機械

 - HPACK
   - ヘッダを圧縮したいがふつうの圧縮は圧縮率観測攻撃に負けるので、負けないのを作った
   - 圧縮方式は 4つのアルゴリズムの組合せ
   - ぜいたくを言わなければそこそこ手抜き可能


* HTTP2 threats
  - HTTPSへの攻撃: BEAST CRIME BREACH があった
  - BEAST は chosen plaintext attack
  - CRIME は compression への攻撃
    - 同じく chosen plaintext attack
	- captive portal だとはじめの通信は常に同じ
  - BREACH
  - HTTP では cookie を制御しやすい
  
