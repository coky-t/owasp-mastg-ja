# モバイルアプリの暗号化

暗号化はユーザーのデータを保護する上で特に重要な役割を果たします。モバイル環境では、ユーザーのデバイスへの物理的なアクセスを有する攻撃者が想定されるシナリオになります。この章では暗号化の概念の概要とモバイルアプリに関連するベストプラクティスについて説明します。これらのベストプラクティスはモバイルオペレーティングシステムには依存することなく有効です。

## 主要な概念

暗号化の目的は、攻撃に直面しても、機密性、データの完全性、真正性を常に提供することです。機密性は暗号化を使用してデータのプライバシーを確保することです。データの完全性はデータの一貫性と、ハッシュを使用したデータの改竄や改変の検出を扱います。真正性はデータが信頼できるソースから取得されることを保証します。

暗号化アルゴリズムは平文のデータから元の内容を隠す暗号文に変換します。平文のデータは復号化により暗号文から復元できます。暗号化には **対称** (同じ共通鍵 (secret-key) での暗号化と復号化) と **非対称** (公開鍵 (public key) と秘密鍵 (private key) のペアを使用した暗号化と復号化) があります。一般に、暗号化操作は完全性を保護しませんが、一部の対称暗号化モードでも保護が機能します。

**対称鍵暗号アルゴリズム** は暗号化と復号化の両方に同じ鍵を使用します。このタイプの暗号化は高速でありバルクデータ処理に適しています。鍵にアクセスするすべての人が暗号化されたコンテンツを復号化できるため、この方式では鍵管理を慎重に行い、鍵配布を一元管理する必要です。

**公開鍵暗号アルゴリズム** は二つの個別の鍵、公開鍵 (public key) と秘密鍵 (private key) で動作します。公開鍵 (public key) は自由に配布できますが、秘密鍵 (private key) は誰とも共有すべきではありません。公開鍵 (public key) で暗号化されたメッセージは秘密鍵 (private key) でのみ解読でき、その逆も可能です。非対称暗号化は対称操作よりも数倍遅いため、通常はバルク暗号化のための対称鍵などの少量のデータを暗号化するためにのみ使用されます。

**ハッシュ化** は暗号化の形式ではありませんが、暗号化を使用しています。ハッシュ関数は任意のデータを固定長の値に決定論的にマップします。入力からハッシュを計算することは簡単ですが、ハッシュから元の入力を決定することは非常に困難 (つまり実行不可能) です。さらに、入力が一ビットでも変化するとハッシュは完全に変化してしまいます。ハッシュ関数は完全性検証に使用されますが、真正性の保証を提供しません。

**メッセージ認証コード** (MAC) は (対称暗号化やハッシュなどの) 他の暗号化メカニズムを共通鍵 (secret key) と組み合わせて、完全性と真正性の両方の保護を提供します。しかし、MAC を検証するには、複数のエンティティが同じ共通鍵 (secret key) を共有する必要があり、それらのエンティティのいずれかが有効な MAC を生成します。最も一般的に使用されるタイプの MAC である HMAC は基となる暗号化プリミティブとしてハッシュ化に依存します。HMAC アルゴリズムの完全な名前には元となるハッシュ関数のタイプが含まれます (例えば、HMAC-SHA256 は SHA-256 ハッシュ関数を使用します) 。

**署名** は非対称暗号化 (つまり、公開鍵 (public key) と秘密鍵 (private key) のペアを使用) をハッシュ化と組み合わせて、秘密鍵 (private key) でメッセージのハッシュを暗号化することにより完全性と真正性を提供します。しかし、MAC とは異なり、秘密鍵 (private key) はデータ署名者にとって一意であり続けることから、署名は否認防止プロパティも提供します。

**鍵導出関数** (KDF) は (パスワードなどの) 秘密の値から共通鍵 (secret key) を導出し、鍵を他の形式に変換したり長さを増やしたりするために使用されます。KDF はハッシュ関数に似ていますが、他の用途もあります (例えば、マルチパーティ鍵共有プロトコルのコンポーネントとして使用されています) 。ハッシュ関数と KDF は両方ともリバースすることは困難である必要がありますが、KDF には生成する鍵にランダム性が必要であるという追加要件があります。

<br/>
<br/>
<br/>

## 非セキュアな暗号アルゴリズムや非推奨の暗号アルゴリズムの特定 (MSTG-CRYPTO-4)

モバイルアプリを評価する際には、重大な既知の脆弱性や現代のセキュリティ要件には不十分な暗号アルゴリズムを使用していないことを確認する必要があります。過去にセキュアであると考えられていたアルゴリズムが時間と共にセキュアではなくなる可能性があります。したがって、現在のベストプラクティスを定期的に確認し、それに応じて設定を調整することが重要です。

暗号アルゴリズムが最新で業界標準に適合していることを確認します。脆弱なアルゴリズムには古いブロック暗号 (DES や 3DES など)、ストリーム暗号 (RC4 など)、ハッシュ関数 (MD5 や SHA1 など)、不十分な乱数生成器 (Dual_EC_DRBG や SHA1PRNG など) があります。(NIST などにより) 認定されたアルゴリズムでさえ時間の経過とともにセキュアではなくなる可能性があることに注意します。認定はアルゴリズムの堅牢性の定期的な検証に取って代わるものではありません。既知の脆弱性を持つアルゴリズムはよりセキュアなものに置き換えるべきです。さらに、暗号化に使用されるアルゴリズムは標準化され、検証が可能でなければなりません。未知のアルゴリズムや独自のアルゴリズムを使用してデータを暗号化すると、アプリケーションはさまざまな暗号化攻撃にさらされ、平文に復元される可能性があります。

アプリのソースコードを調査し、以下のような既知の脆弱な暗号アルゴリズムのインスタンスを特定します。

- [DES, 3DES](https://www.enisa.europa.eu/publications/algorithms-key-size-and-parameters-report-2014 "ENISA Algorithms, key size and parameters report 2014")
- RC2
- RC4
- [BLOWFISH](https://www.enisa.europa.eu/publications/algorithms-key-size-and-parameters-report-2014 "ENISA Algorithms, key size and parameters report 2014")
- MD4
- MD5
- SHA1

暗号化 API の名前はモバイルプラットフォームごとに異なります。

以下を確認してください。

- 暗号アルゴリズムは最新で業界標準に適合している。これには、古いブロック暗号 (DES など)、ストリーム暗号 (RC4 など)、ハッシュ関数 (MD5 など)、Dual_EC_DRBG などの不十分な乱数生成器など (NIST に認定されているものさえ) があります。これらはすべてセキュアではないとマークされるべきであり、使用すべきではなく、アプリケーションやサーバーから削除されるべきです。
- 鍵長は業界標準と適合していて十分な時間の保護を提供している。さまざまな鍵長とムーアの法則を考慮した保護の比較が [オンライン](https://www.keylength.com/ "Keylength comparison") にあります。
- 暗号化の手段を他のものと混在させない。例えば、公開鍵で署名してはいけません。また、署名に使用した鍵ペアを暗号化に再利用しようとしてはいけません。
- 暗号パラメータは妥当な範囲内で十分に定義されている。これには、暗号ソルト (少なくともハッシュ関数出力と同じ長さであるべき) 、パスワード導出関数および反復カウントの妥当な選択 (PBKDF2, scrypt, bcrypt など) 、ランダムかつユニークな IV、目的に合ったブロック暗号モード (特定の場合を除き、ECB を使用すべきでないなど) 、適切な鍵管理 (3DES は三つの独立した鍵を持つべきなど) などがあります。

以下のアルゴリズムが推奨されます。

- 機密性アルゴリズム: AES-GCM-256 または ChaCha20-Poly1305
- 完全性アルゴリズム: SHA-256, SHA-384, SHA-512, BLAKE3, SHA-3 ファミリー
- デジタル署名アルゴリズム: RSA (3072 ビット以上), ECDSA with NIST P-384
- 鍵共有アルゴリズム: RSA (3072 ビット以上), DH (3072 ビット以上), ECDH with NIST P-384

さらに、暗号鍵の格納、暗号操作の実行などのために、(利用可能な場合) セキュアハードウェアに常に依拠するべきです。

アルゴリズムの選択とベストプラクティスの詳細については、以下のリソースを参照してください。

- ["Commercial National Security Algorithm Suite and Quantum Computing FAQ"](https://cryptome.org/2016/01/CNSA-Suite-and-Quantum-Computing-FAQ.pdf "Commercial National Security Algorithm Suite and Quantum Computing FAQ")
- [NIST recommendations (2019)](https://www.keylength.com/en/4/ "NIST recommendations")
- [BSI recommendations (2019)](https://www.keylength.com/en/8/ "BSI recommendations")

## よくある設定の問題 (MSTG-CRYPTO-1, MSTG-CRYPTO-2, MSTG-CRYPTO-3)

### 不十分な鍵長

もっともセキュアな暗号アルゴリズムであっても、アルゴリズムが不十分な鍵サイズを使用する場合、ブルートフォース攻撃に対して脆弱になります。

鍵長が [許容される業界標準](https://www.enisa.europa.eu/publications/algorithms-key-size-and-parameters-report-2014 "ENISA Algorithms, key size and parameters report 2014") を満たしていることを確認します。

### ハードコードされた暗号鍵による対称暗号化

対称暗号化と鍵付きハッシュ (MAC) のセキュリティは鍵の秘密性に大きく依存します。鍵が開示されている場合、暗号化により得られるセキュリティは失われます。これを防ぐには、作成した暗号化データと同じ場所に共通鍵 (secret key) を保存しないことです。よくある間違いは静的でハードコードされた暗号化鍵を使用してローカルに保存されたデータを暗号化したり、アプリに鍵をコンパイルすることです。これにより鍵は逆アセンブラを使用できるすべての人がアクセスできるようになります。

ハードコードされた暗号化鍵とは鍵が以下のとおりであることを意味します。

- アプリケーションリソースの一部である
- 既知の値から導出できる値である
- コードにハードコーディングされている

まず、鍵やパスワードがソースコードに格納されていないことを確認します。これは、ネイティブコード、JavaScript/Dart コード、Android の Java/Kotlin コード、iOS の Objective-C/Swift を確認する必要があることを意味します。ハードコードされた鍵はソースコードが難読化されていたとしても問題であることに注意します。難読化は動的計装により容易にバイパスできるためです。

アプリが双方向 TLS (サーバー証明書とクライアント証明書の両方が検証されている) を使用している場合、以下を確認します。

- クライアント証明書のパスワードがローカルに保存されていないこと、またはデバイスキーチェーンにロックされていること。
- クライアント証明書がすべてのインストールで共有されていないこと。

アプリがアプリデータに格納されている追加の暗号化されたコンテナに依存している場合には、暗号化鍵の使用方法を確認します。鍵ラッピングスキームが使用されている場合、マスターシークレットがユーザーごとに初期化されていること、またはコンテナが新しい鍵で再暗号化されていることを確認します。マスターシークレットや以前のパスワードを使用してコンテナを復号化できる場合には、パスワードの変更がどのように処理されるかを確認します。

モバイルアプリで対称暗号化が使用されるときには常に共通鍵 (secret key) をセキュアなデバイスストレージに保存する必要があります。プラットフォーム固有の API の詳細については、"[Android のデータストレージ](0x05d-Testing-Data-Storage.md)" および "[iOS のデータストレージ](0x06d-Testing-Data-Storage.md)" の章を参照してください。

### 脆弱な鍵生成関数

暗号アルゴリズム (対称暗号化や一部の MAC など) では所定のサイズの秘密の入力が必要です。例えば、AES は正確に 16 バイトの鍵を使用します。ネイティブ実装ではユーザーが入力したパスワードを入力鍵として直接使用することがあります。ユーザーが入力したパスワードを入力鍵として使用することには以下の問題があります。

- パスワードが鍵よりも小さい場合、鍵空間全体が使用されません。残りの空間は詰められます (パディングには空白を使用することがよくあります) 。
- ユーザーが入力したパスワードは現実的にはほとんどが表示可能かつ発音可能な文字で構成されます。したがって、可能な 256 の ASCII 文字のいくつかのみが使用され、エントロピーはおよそ四分の一に減少します。

パスワードが暗号化関数に直接渡されないことを確認します。代わりに、ユーザーが入力したパスワードを KDF に渡して暗号鍵を作成すべきです。パスワード導出関数を使用する際には適切な反復回数を選択します。例えば、[NIST は PBKDF2 について少なくとも 10,000 回の反復を推奨](https://pages.nist.gov/800-63-3/sp800-63b.html#sec5 "NIST Special Publication 800-63B") しており、[ユーザーが感じるパフォーマンスがクリティカルではない重要な鍵に対しては少なくとも 10,000,000 回](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf "NIST Special Publication 800-132") としています。重要な鍵については [Argon2](https://github.com/p-h-c/phc-winner-argon2 "Argon2") などの [Password Hashing Competition (PHC)](https://password-hashing.net/ "PHC") で認められたアルゴリズムの実装を検討することをお勧めします。

### 脆弱な乱数生成器

決定性のデバイスで真の乱数を生成することは基本的に不可能です。擬似乱数生成器 (RNG) は擬似乱数ストリームを生成することでこれを補うものです。擬似乱数ストリームはランダムに生成されているように見える数値のストリームです。生成される数値の品質は使用されるアルゴリズムのタイプにより異なります。暗号論的にセキュアな RNG は統計的ランダム性テストに合格する乱数を生成し、予測攻撃に対して耐性があります (例えば、次に生成される数を予測することは統計的に実行不可能です) 。

モバイル SDK では十分な人工のランダム性を持つ数値を生成する RNG アルゴリズムの標準実装を提供しています。利用可能な API については Android および iOS 固有のセクションで説明します。

### 暗号のカスタム実装

独自の暗号化機能を生み出すには時間がかかり、困難であり、失敗する可能性が高くなります。代わりに広くセキュアであるとみなされている既知のアルゴリズムを使用します。モバイルオペレーティングシステムはこれらのアルゴリズムを実装する標準の暗号 API を提供します。

ソースコード内で使用されているすべての暗号手法、特に機密データに直接適用されているものを注意深く調べます。すべての暗号操作は Android および iOS の標準暗号 API を使用すべきです (プラットフォーム固有の章で詳細に説明します) 。既知のプロバイダから標準ルーチンを呼び出さない暗号操作は厳密に検査すべきです。改変された標準アルゴリズムに細心の注意を払います。エンコーディングは暗号化ではないことを忘れないでください。XOR (排他的 OR) などのビット操作演算子を見つけたら常にさらに調査します。

すべての暗号実装では、以下のことが常に行われるようにする必要があります。

- 一時鍵 (AES/DES/Rijndael の中間/導出鍵など) は使用後またはエラーの場合にメモリから適切に削除されています。
- 暗号の内部状態はできるだけ早くメモリから削除されているべきです。

### 不十分な AES 設定

Advanced Encryption Standard (AES) はモバイルアプリの対称暗号化のために広く受け入れられている標準規格です。これは一連のリンクされた数学演算に基づく反復ブロック暗号です。AES は入力上で可変数のラウンドを実行します。各ラウンドは入力ブロック内のバイトの交換と並び替えを行います。各ラウンドは元の AES 鍵から派生した 128 ビットのラウンド鍵を使用します。

この執筆時点では、AES に対する効率的な暗号解読攻撃は発見されていません。しかし、実装の詳細やブロック暗号モードなどの設定可能なパラメータには何かしらのエラーがある可能性があります。

#### 脆弱なブロック暗号モード

ブロックベースの暗号化は離散入力ブロック (例えば、AES は 128 ビットブロックを有する) に対して実行されます。平文がブロックサイズよりも大きい場合、その平文は与えられた入力サイズのブロックに内部的に分割され、各ブロックで暗号化が実行されます。ブロック暗号利用モード (またはブロックモード) は前のブロックを暗号化した結果が次のブロックに影響するかどうかを決定します。

[ECB (Electronic Codebook)](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_Codebook_.28ECB.29 "Electronic Codebook (ECB)") は入力を固定サイズのブロックに分割し、同じ鍵を使用して個別に暗号化されます。複数の分割ブロックが同じ平文を含む場合、それらは同じ暗号文ブロックに暗号化され、データ内のパターンを特定しやすくなります。状況によっては、攻撃者が暗号化されたデータを再生できる可能性もあります。

<img src="Images/Chapters/0x07c/EncryptionMode.png" width="550px" />

Cipher Block Chaining (CBC) が ECB の代わりに使用されていることを確認します。CBC モードでは、平文ブロックは前の暗号文ブロックと XOR されます。これにより、ブロックに同じ情報が含まれていても、暗号化された各ブロックは一意でありランダム化されます。パディングオラクル攻撃に対する耐性を高めるために、CBC と HMAC を組み合わせることや、「パディングエラー」、「MAC エラー」、「復号化失敗」などのエラーが発生しないようにすることがベストであることに注意してください。

暗号化されたデータを保存する場合には、Galois/Counter Mode (GCM) など、保存されたデータの完全性も保護するブロックモードを使用することをお勧めします。最後のものはそのアルゴリズムが各 TLSv1.2 実装に必須であるという副次の利点があり、すべての最新のプラットフォームで利用できます。

効果的なブロックモードの詳細については、[NIST のブロックモード選択のガイドライン](https://csrc.nist.gov/groups/ST/toolkit/BCM/modes_development.html "NIST Modes Development, Proposed Modes") を参照してください。

#### 予測可能な初期化ベクトル

CBC, OFB, CFB, PCBC, GCM モードでは暗号の初期入力として初期化ベクトル (IV) が必要です。IV は秘密であり続ける必要はありませんが、予測可能であってはいけません。暗号化されたメッセージごとにランダムで一意であり、繰り返し不可であるべきです。IV が暗号論的にセキュアな乱数生成器を使用して生成されていることを確認します。IV の詳細については、[Crypto Fail の初期化ベクトルの記事](http://www.cryptofails.com/post/70059609995/crypto-noobs-1-initialization-vectors "Crypto Noobs #1: Initialization Vectors") を参照してください。

コードで使用される暗号化ライブラリに注意してください。多くのオープンソースライブラリはバッドプラクティス (ハードコードされた IV の使用など) となる可能性のある例をドキュメントで提供しています。よくある間違いは IV 値を変更せずにサンプルコードをコピーペーストすることです。

#### ステートフル操作モードでの初期化ベクトル

CTR および GCM モードを使用する場合、IV の使用法は異なることに注意してください。初期化ベクトルは多くの場合カウンタ (ノンスと組み合わせた CTR) となります。したがって、自身のステートフルモードで予測可能な IV を使用することはまさに必要とされるものです。CTR では新しいブロック操作ごとにカウンタを足した新しいノンスを入力として持ちます。例えば、5120 ビット長の平文の場合、20 のブロックがあるため、ノンスとカウンタで構成される 20 の入力ベクトルを必要とします。一方 GCM では暗号操作ごとに一つの IV を持ちますが、同じ鍵を繰り返すべきではありません。IV の詳細と勧告については [NIST の GCM の文書](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode and GMAC") のセクション 8 を参照してください。

### 脆弱なパディングやブロック操作の実装によるパディングオラクル攻撃

非対称暗号を行う際に、以前は パディングメカニズムとして [PKCS1.5](https://tools.ietf.org/html/rfc2313 "PCKS1.5 in RFC2313") パディング (コード内では `PKCS1Padding`) が使用されていました。現在の Java 環境では PKCS #5 として参照しています。このメカニズムはパディングオラクル攻撃に対して脆弱です。したがって、[PKCS#1 v2.0](https://tools.ietf.org/html/rfc2437 "PKCS1 v2.0 in RFC 2437") (コード内では `OAEPPadding`, `OAEPwithSHA-256andMGF1Padding`, `OAEPwithSHA-224andMGF1Padding`, `OAEPwithSHA-384andMGF1Padding`, `OAEPwithSHA-512andMGF1Padding`) でキャプチャされた OAEP (Optimal Asymmetric Encryption Padding) を使用することがベストです。OAEP を使用している場合でも、[Kudelskisecurity のブログ](https://research.kudelskisecurity.com/2018/04/05/breaking-rsa-oaep-with-mangers-attack/ "Kudelskisecurity") で説明されているように Mangers 攻撃としてよく知られている問題に遭遇する可能性があります。

注意: PKCS #5 を使用する AES-CBC は、「パディングエラー」、「MAC エラー」、「復号化失敗」などの警告が得られる実装であるため、パディングオラクル攻撃に対しても脆弱です。例として [The Padding Oracle Attack](https://robertheaton.com/2013/07/29/padding-oracle-attack/ "The Padding Oracle Attack") および [The CBC Padding Oracle Problem](https://eklitzke.org/the-cbc-padding-oracle-problem "The CBC Padding Oracle Problem") を参照してください。次に、平文を暗号化した後は HMAC を追加することがベストです。つまり、失敗した MAC を含む暗号文は復号化する必要がなくなり、破棄できるようになります。

### ストレージ内およびメモリ内の鍵を保護する

メモリダンプが脅威モデルの一部であるとき、鍵はアクティブに使用される瞬間にアクセスできます。メモリダンプには root アクセス (ルート化デバイスや脱獄済みデバイスなど) または Frida によるパッチ適用済みのアプリケーション (Fridump などのツールを使用できます) のいずれかが必要です。
そのため、デバイスに鍵がまだ必要とされる場合には、以下を考慮することがベストです。

- **リモートサーバー内の鍵**: Amazon KMS や Azure Key Vault などのリモート Key Valut を使用できます。一部のユースケースでは、アプリとリモートリソースの間にオーケストレーションレイヤを開発することが適切な選択肢となることがあります。例えば、Function as a Service (FaaS) システム (AWS Lambda や Google Cloud Functions など) 上で動作するサーバーレス関数が API キーやシークレットを取得するためにリクエストを転送するような場合です。Amazon Cognito, Google Identity Platform, Azure Active Directory などの他の選択肢があります。
- **セキュアハードウェア支援のストレージ内の鍵**: すべての暗号化アクションおよびその鍵自体が Trusted Execution Environment (例、 [Android Keystore](https://developer.android.com/training/articles/keystore.html "Android keystore system") を使用する) や [Secure Enclave](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/storing_keys_in_the_secure_enclave "Storing Keys in the Secure Enclave") (例、キーチェーンを使用する) にあることを確認します。詳細については [Android のデータストレージ](0x05d-Testing-Data-Storage.md#storing-a-key---example) や [iOS のデータストレージ](0x06d-Testing-Data-Storage.md#the-keychain) の章を参照してください。
- **エンベロープ暗号化によって保護される鍵**: 鍵が TEE / SE の外部に保存される場合、多層暗号化の使用を検討してください。 _エンベロープ暗号化_ アプローチ ([OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#encrypting-stored-keys "OWASP Cryptographic Storage Cheat Sheet: Encrypting Stored Keys"), [Google Cloud Key management guide](https://cloud.google.com/kms/docs/envelope-encryption?hl=en "Google Cloud Key management guide: Envelope encryption"), [AWS Well-Architected Framework guide](https://docs.aws.amazon.com/wellarchitected/latest/financial-services-industry-lens/use-envelope-encryption-with-customer-master-keys.html "AWS Well-Architected Framework")), [a HPKE approach](https://tools.ietf.org/html/draft-irtf-cfrg-hpke-08 "Hybrid Public Key Encryption") を参照) でデータ暗号鍵を鍵暗号鍵で暗号化します。
- **メモリ内の鍵**: 鍵がメモリ内にある時間をできる限り短くし、暗号化操作に成功した後やエラーの場合に鍵をゼロ埋めして無効にすることを検討します。一般的な暗号化ガイドラインについては、 [Clean memory of secret data](https://github.com/veorq/cryptocoding#clean-memory-of-secret-data/ "The Cryptocoding Guidelines by @veorq: Clean memory of secret data") を参照してください。詳細について、Android の場合は [Testing Memory for Sensitive Data](0x05d-Testing-Data-Storage.md#testing-memory-for-sensitive-data-mstg-storage-10) 、iOS の場合は [Testing Memory for Sensitive Data](0x06d-Testing-Data-Storage.md#testing-memory-for-sensitive-data-mstg-storage-10) のセクションを参照してください。

注意: メモリダンプの容易さを考えると、署名の検証や暗号化に使用される公開鍵以外では、アカウントやデバイス間で同じ鍵を共有してはいけません。

### 転送時の鍵を保護する

あるデバイスから別のデバイスへ、またはアプリからバックエンドへ鍵を転送する必要がある場合は、転送鍵ペアまたは別のメカニズムを使用して、適切な鍵保護が設定されていることを確認します。鍵は簡単にリバースできる難読化手法で共有されることがよくあります。そうではなく、非対称暗号方式またはラッピング鍵が使用されていることを確認します。例えば、対称鍵は非対称鍵ペアの公開鍵で暗号化できます。

## Android と iOS の暗号化 API

同じ基本的な暗号原則が特定の OS とは独立して適用されますが、それぞれのオペレーティングシステムは独自の実装と API を提供します。データストレージ用のプラットフォーム固有の暗号化 API については "[Android のデータストレージ](0x05d-Testing-Data-Storage.md)" および "[iOS のデータストレージ](0x06d-Testing-Data-Storage.md)" の章で詳しく説明しています。ネットワークトラフィックの暗号化、特に Transport Layer Security (TLS) については "[Android のネットワーク API](0x05g-Testing-Network-Communication.md)" の章で説明しています。

## 暗号化ポリシー

大規模な組織で、または高リスクのアプリケーションが作成される場合、[NIST 鍵管理における推奨事項](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r4.pdf "NIST 800-57 Rev4") のようなフレームワークに基づいて、暗号化ポリシーを作成することがよくあります。暗号化の適用に基本的な誤りが見つかった場合、学んだ教訓や暗号鍵管理方針を設定する良い出発点となります。

## 暗号技術に関する規制

App Store や Google Play にアプリをアップロードする場合、一般的にアプリは米国のサーバーに保存されます。アプリに暗号が含まれ、他の国に配布される場合、暗号の輸出とみなされます。これは米国の暗号技術輸出規制に従う必要があることを意味します。また、一部の国では暗号に関する輸入規制があります。

詳しくはこちら。

- [Complying with Encryption Export Regulations (Apple)](https://developer.apple.com/documentation/security/complying_with_encryption_export_regulations "Complying with Encryption Export Regulations")
- [Export compliance overview (Apple)](https://help.apple.com/app-store-connect/#/dev88f5c7bf9 "Export compliance overview")
- [Export compliance (Google)](https://support.google.com/googleplay/android-developer/answer/113770?hl=en "Export compliance")
- [Encryption and Export Administration Regulations (USA)](https://www.bis.doc.gov/index.php/policy-guidance/encryption "Encryption and Export Administration Regulations")
- [Encryption Control (France)](https://www.ssi.gouv.fr/en/regulation/cryptology/ "Encryption Control")
- [World map of encryption laws and policies](https://www.gp-digital.org/WORLD-MAP-OF-ENCRYPTION/)

## 参考情報

### OWASP MASVS

- MSTG-ARCH-8: "暗号鍵が（もしあれば）どのように管理されるかについての明確な方針があり、暗号鍵のライフサイクルが施行されている。 NIST SP 800-57 などの鍵管理標準に準拠することが理想的である。"
- MSTG-CRYPTO-1: "アプリは暗号化の唯一の方法としてハードコードされた鍵による対称暗号化に依存していない。"
- MSTG-CRYPTO-2: "アプリは実績のある暗号化プリミティブの実装を使用している。"
- MSTG-CRYPTO-3: "アプリは特定のユースケースに適した暗号化プリミティブを使用している。業界のベストプラクティスに基づくパラメータで構成されている。"
- MSTG-CRYPTO-4: "アプリはセキュリティ上の目的で広く非推奨と考えられる暗号プロトコルやアルゴリズムを使用していない。"

### 暗号化

- [Argon2](https://github.com/p-h-c/phc-winner-argon2 "Argon2")
- [AWS Well-Architected Framework guide](https://docs.aws.amazon.com/wellarchitected/latest/financial-services-industry-lens/use-envelope-encryption-with-customer-master-keys.html "AWS Well-Architected Framework")
- [Breaking RSA with Mangers Attack]( https://research.kudelskisecurity.com/2018/04/05/breaking-rsa-oaep-with-mangers-attack/ "Mangers attack")
- [Google Cloud Key management guide](https://cloud.google.com/kms/docs/envelope-encryption?hl=en "Google Cloud Key management guide: Envelope encryption")
- [Hybrid Public Key Encryption](https://tools.ietf.org/html/draft-irtf-cfrg-hpke-08 "Hybrid Public Key Encryption")
- [NIST 800-38d](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf "NIST 800-38d")
- [NIST 800-57Rev5](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final "NIST 800-57Rev5")
- [NIST 800-63b](https://pages.nist.gov/800-63-3/sp800-63b.html "NIST 800-63b")
- [NIST 800-132](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf "NIST 800-132")
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#encrypting-stored-keys "OWASP Cryptographic Storage Cheat Sheet: Encrypting Stored Keys")
- [Password Hashing Competition(PHC)](https://password-hashing.net "PHC")
- [PKCS #1: RSA Encryption Version 1.5](https://tools.ietf.org/html/rfc2313 "PKCS #1: RSA Encryption Version 1.5")
- [PKCS #1: RSA Cryptography Specifications Version 2.0](https://tools.ietf.org/html/rfc2437 "PKCS #1: RSA Cryptography Specifications Version 2.0")
- [PKCS #7: Cryptographic Message Syntax Version 1.5](https://tools.ietf.org/html/rfc2315 "PKCS #7")
- [The Padding Oracle Attack](https://robertheaton.com/2013/07/29/padding-oracle-attack "The Padding Oracle Attack")
- [The CBC Padding Oracle Problem](https://eklitzke.org/the-cbc-padding-oracle-problem "The CBC Padding Oracle Problem")
- [@veorq's Cryptocoding Guidelines](https://github.com/veorq/cryptocoding "The Cryptocoding Guidelines by @veorq")
