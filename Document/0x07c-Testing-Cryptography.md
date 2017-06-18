## モバイルアプリでの暗号化

以下の章では MASVS の暗号化要件の技術的なテストケースを説明します。この章に記載されているテストケースは一般的な暗号の概念に基づいており、iOS や Android の特定の実装に依存していません。

The primary goal of cryptography is to provide confidentiality, data integrity, and authentication, even in the presence of a malicious attacker. Confidentiality is achieved through use of encryption, with the aim of ensuring secrecy of the contents. Data integrity deals with maintaining and ensuring consistency of data and detection of tampering/modification. Authentication ensures that the data came from a trusted source.

Encryption converts the plain-text data into a form (called cipher text) that does not reveal any information about the original contents. The original data can be restored from the cipher text through decryption. Two main forms of encryption are symmetric (or secret key) and asymmetric (or public key).

* Symmetric-key encryption algorithms use the same key for both encryption and decryption. Since everybody who has access to the key is able to decrypt the encrypted content, they require careful key management.
* Public-key (or asymmetric) encryption algorithms operate with two separate keys: the public key and the private key. The public key can be distributed freely, while the private key should not be shared with anyone. A message encrypted with the public key can only be decrypted with the private key.

Hash functions deterministically map arbitrary pieces of data into fixed-length values. It is typically easy to compute the hash, but difficult (or impossible) to determine the original input based on the hash. Cryptographic hash functions additionally guarantee that even small changes to the input data result in large changes to the resulting hash values. Cryptographic hash functions are used for authentication, data verification, digital signatures, message authentication codes, etc.

Two uses of cryptography are covered in other chapters:
* Secure communications. TLS (Transport Layer Security) uses both symmetric and public-key cryptography.
* Secure storage. Android and iOS both support disk and file encryption. In addition, they also provide secure data storage (Keychain and Keystore) capabilities.

Other uses of cryptography require careful adherence to best practices:
* For encryption, use a strong, modern cipher with the appropriate, secure mode and a strong key. Examples:
  - 256-bit key AES in GCM mode (provides both encryption and integrity verification.)
  - 4096-bit RSA with OAEP padding.
  - 224/256-bit elliptic curve cryptography.
* Do not use known weak algorithms. For example:
  - AES in ECB mode is not considered secure, because it leaks information about the structure of the original data.
  - Several other AES modes can be weak.
  - RSA with 768-bit and weaker keys can be broken. Older PKCS#1 padding leaks information.
* Rely on secure hardware, if available, for storing encryption keys, performing cryptographic operations, etc.

#### References

[1] Best Practices for Security & Privacy: Cryptography - https://developer.android.com/training/articles/security-tips.html#Crypto

### 暗号のカスタム実装に関するテスト

#### 概要

非標準の暗号アルゴリズムやカスタムビルドの暗号アルゴリズムの使用は危険です。特定の攻撃者がアルゴリズムを破り、保護されているデータを侵害する可能性があります。暗号化機能の実装には時間がかかり、困難であり、失敗する可能性が非常に高くなります。代わりに既にセキュアであることが証明されている既知のアルゴリズムを使用すべきです。すべての成熟したフレームワークやライブラリはモバイルアプリを実装する際にも使用すべき暗号化機能を提供します。

#### 静的解析

ソースコードに含まれるすべての暗号手法、特に機密データに直接適用されている手法を注意深く調べます。一見標準のようにみえるが改変されたアルゴリズムに細心の注意を払います。エンコーディングは暗号化ではないことを忘れないでください。XOR (排他的 OR) などのビット操作演算子が現れたら深く掘り下げてみる良い兆候かもしれません。

#### 改善方法

カスタム暗号アルゴリズムを開発してはいけません。これは暗号技術者によりよく知られている攻撃を受ける可能性が高いためです。その分野の専門家により現在強力であると考えられている十分に検証されたアルゴリズムを選択し、十分にテストされた実装を使用します。

#### 参考情報

##### OWASP Mobile Top 10 2016
* M6 - Broken Cryptography

##### OWASP MASVS
- V3.2: "アプリは実績のある暗号プリミティブの実装を使用している。"

##### CWE
* CWE-327: Use of a Broken or Risky Cryptographic Algorithm

##### その他
[1] Supported Ciphers in KeyStore - https://developer.android.com/training/articles/keystore.html#SupportedCiphers

### 安全ではない暗号アルゴリズムや廃止された暗号アルゴリズムに関するテスト

#### 概要

多くの暗号アルゴリズムやプロトコルは使用すべきではありません。それらには重大な脆弱性があることが示されているか、現代のセキュリティ要件には不十分であるためです。以前はセキュアであると考えられていたアルゴリズムが時間の経過とともにセキュアではなくなることがあります。したがって、最新のベストプラクティスを定期的に確認し、それに応じて設定を調整することが重要です。

#### 静的解析

ソースコードは暗号アルゴリズムが最新で業界標準に適合していることを確認されるべきです。これには、古いブロック暗号 (DES など)、ストリーム暗号 (RC4 など)、ハッシュ関数 (MD5 など)、Dual_EC_DRBG などの不十分な乱数生成器が含まれますが、これに限定されません。NIST などにより認定されたアルゴリズムは時間の経過とともにセキュアではなくなる可能性があることにも注意します。認定はアルゴリズムの堅牢性の定期的な検証に置き換えられるものではありません。これらはすべてセキュアではないとマークすべきであり、使用すべきではなく、アプリケーションコードベースから削除すべきです。

ソースコードを調査し、アプリケーション全体の暗号アルゴリズムのインスタンスを特定し、以下のような既知の脆弱なものを探します。

* DES, 3DES <sup>[6]</sup>
* RC2
* RC4
* BLOWFISH <sup>[6]</sup>
* MD4
* MD5
* SHA1 など

On Android (via Java Cryptography APIs), selecting an algorithm is done by requesting an instance of the `Cipher` (or other primitive) by passing a string containing the algorithm name. For example, `Cipher cipher = Cipher.getInstance("DES");`. On iOS, algorithms are typically selected using predefined constants defined in CommonCryptor.h, e.g., `kCCAlgorithmDES`. Thus, searching the source code for the presence of these algorithm names would indicate that they are used. Note that since the constants on iOS are numeric, an additional check needs to be performed to check whether the algorithm values sent to CCCrypt function map to one of the deprecated/insecure algorithms.

#### 動的解析

カスタム暗号化方式の使用について、APK を逆コンパイルして得られたソースコードを調べることをお勧めします(「静的解析」を参照ください)。

テスト中にローカルに格納されているデータに遭遇した場合には、使用されているアルゴリズムを特定し、既知のセキュアではないアルゴリズムのリストと比較して検証します。

#### 改善方法

暗号化が廃止されたものではないことを定期的に確認します。かつては何年もの計算時間を要すると考えられていた一部の古いアルゴリズムは、数日または数時間で破られる可能性があります。これには以前は強力であると考えられていた MD4, MD5, SHA1, DES やその他のアルゴリズムが含まれます。現在推奨されるアルゴリズムの例です <sup>[1] [2]</sup> ：

* 機密性: AES-GCM-256, ChaCha20-Poly1305
* 完全性: SHA-256, SHA-384, SHA-512, Blake2
* デジタル署名: RSA (3072 ビット以上), ECDSA with NIST P-384
* 鍵共有: RSA (3072 ビット以上), DH (3072 ビット以上), ECDH with NIST P-384

#### 参考情報

##### OWASP Mobile Top 10
* M6 - Broken Cryptography

##### OWASP MASVS
- V3.3: "アプリは特定のユースケースに適した暗号化プリミティブを使用している。業界のベストプラクティスに基づくパラメータで構成されている。"
- V3.4: "アプリはセキュリティ上の目的で広く廃止対象と考えられる暗号プロトコルやアルゴリズムを使用していない。"

##### CWE
* CWE-326: Inadequate Encryption Strength
* CWE-327: Use of a Broken or Risky Cryptographic Algorithm

##### その他
- [1] Commercial National Security Algorithm Suite and Quantum Computing FAQ - https://cryptome.org/2016/01/CNSA-Suite-and-Quantum-Computing-FAQ.pdf
- [2] NIST Special Publication 800-57 - http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r4.pdf
- [4] NIST recommendations (2016) - https://www.keylength.com/en/4/
- [5] BSI recommendations (2017) - https://www.keylength.com/en/8/
- [6] Sweet32 attack -- https://sweet32.info/

##### ツール
* QARK - https://github.com/linkedin/qark
* Mobile Security Framework - https://github.com/ajinabraham/Mobile-Security-Framework-MobSF


### 対称暗号化または MAC が使用されている場合、ハードコードされた秘密鍵に関するテスト

#### 概要

対称暗号化と鍵付きハッシュ (MAC) のセキュリティは使用されている秘密鍵の秘密性に大きく依存します。秘密鍵が開示されている場合、暗号化や MAC により得られるセキュリティはゼロになります。

これは秘密鍵が保護されており、暗号化されたデータとともに格納すべきではないことを要求します。

#### 静的解析

使用されているソースコードに対して以下のチェックを行います。

* 鍵やパスワードがハードコードされておらず、ソースコード内に格納されていないことを確認します。ソースコードで有効になっている管理者アカウントやバックドアアカウントには特に注意します。アプリケーション内の固定ソルトやパスワードハッシュの格納が問題を引き起こすこともあります。
*
* ソースコードに難読化された鍵やパスワードがないことを確認します。難読化は動的計装により簡単にバイパスされるため、基本的にハードコードされた鍵とかわりません。
*
* アプリケーションが双方向 SSL を使用している場合 (つまり、サーバー証明書とクライアント証明書の両方が検証されている場合)、以下をチェックします。
   * クライアント証明書のパスワードがローカルに保存されていないこと、キーチェーンにあるべきです
   * クライアント証明書はすべての装置で共有されていないこと (アプリ内にハードコードされているなど)
* アプリがアプリデータに格納されている追加の暗号化コンテナに依存している場合、暗号鍵の使用方法を確認します。
   * 鍵ラッピングスキームが使用されている場合、マスターシークレットが各ユーザーに対して初期化されているか、コンテナが新しい鍵で再暗号化されることを確認します。
   * (特にマスターシークレットや以前のパスワードを使用してコンテナを復号化できる場合、) パスワードの変更がどのように処理されるかを確認します。

モバイルオペレーティングシステムは一般的にキーストアやキーチェーンと呼ばれる秘密鍵のための特別に保護された記憶域を提供します。これらの記憶域は通常のバックアップルーチンの一部ではなく、ハードウェアにより保護される場合もあります。アプリケーションはすべての秘密鍵に対してこの特別な格納場所やメカニズムを使用すべきです。

#### 改善方法

-- TODO --

#### 参考情報

##### OWASP Mobile Top 10

* M6 - Broken Cryptography

##### OWASP MASVS

-- TODO --

##### CWE

-- TODO --

##### その他

* iOS: Managing Keys, Certificates, and Passwords -- https://developer.apple.com/library/content/documentation/Security/Conceptual/cryptoservices/KeyManagementAPIs/KeyManagementAPIs.html
* Android: The Android Keystore System -- https://developer.android.com/training/articles/keystore.html
* Android: Hardware-backed Keystore -- https://source.android.com/security/keystore/

##### ツール

-- TODO --

### 安全ではない暗号アルゴリズム設定と誤用に関するテスト

#### 概要

強力な暗号アルゴリズムを選択するだけでは十分ではありません。多くの場合、そのような堅牢なアルゴリズムのセキュリティはその構成により影響を受けることがあります。暗号アルゴリズムに対して最も顕著なものは使用される鍵長の選択です。

#### 静的解析

ソースコード解析を行い、以下のような検討されていない設定オプションをチェックすべきです。

* 暗号ソルト、少なくともハッシュ関数出力と同じ長さであるべきです
* * パスワード導出関数を使用する場合の反復カウントの合理的な選択
* ランダムかつユニークである IV
* 目的に合ったブロック暗号モード
* 適切に行われている鍵管理

#### 動的解析

解析中にハッシュが抽出され、それらがセキュアではない方法で構成されている場合、hashcat などのブルートフォースパスワードクラッキングツールを使用して、暗号化されたハッシュから元のプレーンテキストパスワードを抽出することができます。hashcat の wiki にはさまざまなアルゴリズムのクラッキング速度の事例があり、これを利用して攻撃者はプレーンテキストパスワードを復元するために必要な工数を見積もることができます。

ブルートフォースツールを利用するには、使用されているハッシュアルゴリズム （MD5 や SHA1 など) を知っている必要があります。この知見がテスト中に収集されない場合には、hashID などのツールを使用して自動的にハッシュアルゴリズムを識別することができます。

#### 改善方法

使用されている鍵長が業界標準 <sup>[6]</sup> を満たしていることを定期的に確認します。

#### 参考情報

##### OWASP Mobile Top 10
* M6 - Broken Cryptography

##### OWASP MASVS
- V3.3: "アプリは特定のユースケースに適した暗号化プリミティブを使用している。業界のベストプラクティスに基づくパラメータで構成されている。"
- V3.4: "アプリはセキュリティ上の目的で広く廃止対象と考えられる暗号プロトコルやアルゴリズムを使用していない。"

##### CWE
* CWE-326: Inadequate Encryption Strength
* CWE-327: Use of a Broken or Risky Cryptographic Algorithm

##### その他
- [1] Commercial National Security Algorithm Suite and Quantum Computing FAQ - https://cryptome.org/2016/01/CNSA-Suite-and-Quantum-Computing-FAQ.pdf
- [2] NIST Special Publication 800-57 - http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r4.pdf
- [3] Security "Crypto" provider deprecated in Android N -  https://android-developers.googleblog.com/2016/06/security-crypto-provider-deprecated-in.html
- [4] NIST recommendations (2016) - https://www.keylength.com/en/4/
- [5] BSI recommendations (2017) - https://www.keylength.com/en/8/
- [6] ENISA Algorithms, key size and parameters report 2014 - https://www.enisa.europa.eu/publications/algorithms-key-size-and-parameters-report-2014

##### ツール
* QARK - https://github.com/linkedin/qark
* Mobile Security Framework - https://github.com/ajinabraham/Mobile-Security-Framework-MobSF
* hashcat - https://hashcat.net/hashcat/
* hashID - https://pypi.python.org/pypi/hashID



### パスワードの保存に KDF (鍵導出関数) 以外のものが使用されているかどうかのテスト

#### 概要

通常のハッシュは速度に関して最適化されます。例えば大きなメディアを短時間で検証するために最適化されているように。パスワードの保存のためには、このプロパティは望ましくありません。攻撃者が取得したパスワードハッシュを (レインボーテーブルを使用したりブルートフォース攻撃を介して) 短時間で解読できることを意味します。例えば、安全でない MD5 ハッシュが使用されている場合、8枚のハイレベルグラフィックカードにアクセスできる攻撃者は1秒当たり200.3ギガのハッシュをテストできます <sup>[1]</sup> 。

その解決策は構成可能な計算時間を持つ鍵導出関数 (KDF) です。これはより大きなパフォーマンスのオーバーヘッドを課し、これは通常の操作では無視できますが、ブルートフォース攻撃を防ぎます。最近開発された Argon2 や scrypt などの鍵導出関数は GPU ベースのパスワードクラッキングに対して強化されています。

#### 静的解析

ソースコードを使用して、ハッシュがどのように計算されているか判断します。安全でないインスタンス化の例は以下のようになります。

```
MessageDigest md = MessageDigest.getInstance("MD5");
md.update("too many secrets");
byte[] digest = md.digest();
```

#### 動的解析

ハッシュが抽出され、それらが安全でない方法で構成されている場合、hashcat などのブルートフォースパスワードクラッキングツールを使用して、暗号化されたハッシュから元のプレーンテキストパスワードを抽出することができます。hashcat の wiki にはさまざまなアルゴリズムのクラッキング速度の事例があり、これを利用して、攻撃者がプレーンテキストのパスワードを復元するために必要な工数を見積もることができます

ブルートフォースツールを利用するには、使用されているハッシュアルゴリズム (MD5 や SHA1 など) を知っている必要があります。この知識がテスト中に収集されない場合、hashID などのツールを使用してハッシュアルゴリズムを自動的に識別することができます。

#### 改善方法

PBKDF2 (RFC 2898<sup>[5]</sup>), Argon2<sup>[4]</sup>, bcrypt<sup>[3]</sup>, scrypt (RFC 7914<sup>[2]</sup>) などの確立した鍵導出関数を使用します。

#### 参考情報

##### OWASP Mobile Top 10

* M6 - Broken Cryptography

##### OWASP MASVS

- V3.3: "アプリは特定のユースケースに適した暗号化プリミティブを使用している。業界のベストプラクティスに基づくパラメータで構成されている。"
- V3.4: "アプリはセキュリティ上の目的で広く廃止対象と考えられる暗号プロトコルやアルゴリズムを使用していない。"

##### CWE

-- TODO --

##### その他

[1] 8x Nvidia GTX 1080 Hashcat Benchmarks -- https://gist.github.com/epixoip/a83d38f412b4737e99bbef804a270c40
[2] The scrypt Password-Based Key Derivation Function -- https://tools.ietf.org/html/rfc7914
[3] A Future-Adaptable Password Scheme -- https://www.usenix.org/legacy/events/usenix99/provos/provos_html/node1.html
[4] https://github.com/p-h-c/phc-winner-argon2
[5] PKCS #5: Password-Based Cryptographic Specification Version 2.0 -- https://tools.ietf.org/html/rfc2898

##### ツール

* hashcat - https://hashcat.net/hashcat/
* hashID - https://pypi.python.org/pypi/hashID

### ユーザー提供の資格情報が鍵マテリアルとして直接使用されていないかどうかのテスト

#### 概要

対称暗号化や MAC などの暗号アルゴリズムは 128 ビットや 256 ビットなどの所定のサイズの秘密の入力を期待しています。単純な実装ではユーザー提供のパスワードを入力鍵として直接使用することがあります。このアプローチにはいくつかの問題があります。

* パスワードが鍵より小さい場合、完全な鍵空間は使用されません (残りは多くの場合スペースで埋められます)。
* ユーザー提供のパスワードは現実的には大部分が表示可能かつ発音可能な文字で構成されます。したがって、完全なエントロピー (すなわち ASCII を使用する場合には 2<sup>8</sup>) ではなく、小さなサブセット (およそ 2<sup>6</sup>) のみが使用されます。
* 二人のユーザーが同じパスワードを選択した場合、攻撃者は暗号化されたファイルと一致させることができます。これはレインボーテーブル攻撃の可能性が広がります。

#### 静的解析

ソースコードを使用して、パスワードが暗号化機能に直接渡されていないことを確認します。


```
String userKeyString = "trustno1"; // given by user
byte[] userKeyByte = userKeyString.getBytes();
byte[] validKey = new byte[16]; // needed input key, filled with 0

System.arraycopy(userKeyByte, 0, validKey, 0, (userKeyByte.length > 16) ? 16 : userKeyByte.length));

Key theAESKEy = new SecretKeySpec(validKey, "AES");
```

#### 動的解析

「パスワードの保存に KDF (鍵導出関数) 以外のものが使用されているかどうかのテスト」にあるように抽出されたハッシュをテストします。ハッシュや KDF が使用されていない場合には、ブルートフォース攻撃や辞書攻撃は鍵空間が縮小されることによりより効率的になります。

#### 改善方法

ユーザー提供のパスワードをソルトされたハッシュ関数もしくは KDF に渡します。その結果を暗号機能の鍵として使用します。

#### 参考情報

##### OWASP Mobile Top 10

* M6 - Broken Cryptography

##### OWASP MASVS

- V3.3: "アプリは特定のユースケースに適した暗号化プリミティブを使用している。業界のベストプラクティスに基づくパラメータで構成されている。"

##### CWE

-- TODO --

##### その他

* Wikipedia -- https://en.wikipedia.org/wiki/Key_stretching

##### ツール

* hashcat - https://hashcat.net/hashcat/
* hashID - https://pypi.python.org/pypi/hashID

### 機密データが完全性を保護されているかどうかのテスト

#### 概要

アプリケーションの攻撃領域は潜在的なすべての入力パスの合計として定義されます。よく忘れられる攻撃ベクトルにはクラウドストレージやローカルファイルストレージなどの安全でない場所に格納されたファイルがあります。

潜在的に安全でない場所に格納されているすべてのデータは完全性を保護すべきです。つまり、データが使用される前にアプリケーションが変更を検出することなく攻撃者がコンテンツを変更できてはいけません。

ほとんどの対策は格納されているデータのチェックサムを計算してから、データをインポートする前に取得したデータのチェックサムを比較することによって機能します。チェックサムやハッシュが安全でない場所にデータとともに格納されている場合、一般的なハッシュアルゴリズムは十分ではありません。それらは秘密鍵を持っていないため、格納されたデータを変更することができる攻撃者は容易にハッシュを再計算して新たに計算されたハッシュを格納することができます。

#### 静的解析

-- TODO --

* 使用されているアルゴリズムについてソースコードを確認します

#### 動的解析

-- TODO --


#### 改善方法

完全性保護について2つの典型的な暗号対策があります。

* MAC (Message Authentication Codes, メッセージ認証コード、鍵付きハッシュとも呼ばれます) はハッシュと秘密鍵を結合します。MAC は秘密鍵が分かっている場合にのみ計算もしくは検証することができます。ハッシュとは対照的に、これは攻撃者が元のデータを改変した後、MAC を容易に計算できないことを意味します。これはアプリケーションが秘密鍵を独自のストレージに格納し、他の当事者がデータの信頼性を検証する必要がない場合に適しています。

* デジタル署名は公開鍵ベースのスキームです。単一の秘密鍵の代わりに、秘密鍵と公開鍵の組み合わせを使用します。署名は秘密鍵を利用して生成され、公開鍵を利用して検証することができます。MAC と同様に、攻撃者は新しい署名を簡単に作成できません。MAC とは対照的に、署名は秘密鍵を開示する必要なしで検証を可能にします。誰もが MAC の代わりに署名を使用しているのはなぜでしょう。主にパフォーマンス上の理由からです。

* もうひとつの可能性として AEAD スキームを使用した暗号化の使用があります (「暗号化がデータの完全性保護を提供しているかどうかのテスト」を参照ください)。

#### 参考情報

##### OWASP Mobile Top 10

* M6 - Broken Cryptography

##### OWASP MASVS

- V3.3: "アプリは特定のユースケースに適した暗号化プリミティブを使用している。業界のベストプラクティスに基づくパラメータで構成されている。"

##### CWE

-- TODO --

##### その他

-- TODO --

##### ツール

-- TODO --


### 暗号化がデータの完全性保護を提供しているかどうかのテスト

#### 概要

暗号化ではデータの完全性は提供されないことに注意します。つまり、攻撃者が暗号テキストを改変してユーザーが改変された暗号テキストを復号した場合、結果のプレーンテキストはがらくたです (但し復号操作自体は正常に実行されます)。

完全性を保護しない対象アルゴリズムの良い例はワンタイムパッドです。このアルゴリズムは入力データを秘密の入力鍵と XOR します。これにより、データの機密性が情報理論上安全であるという暗号テキストが生成されます。つまり、無限の処理能力を持つ攻撃者でも暗号を解読することはできないでしょう。しかし、データ完全性は保護されていません。

例えば、送金額のメッセージがあることをイメージします。額は 1000 ユーロ/ドル となる `0x0011 1110 1000` であり、あなたが使用している秘密鍵は `0x0101 0101 0101` (それほどランダムではないことは承知しています) とします。これらの2つを XOR すると転送メッセージは `0x0110 1011 1101` になります。攻撃者はプレーンテキストの内容を知りません。しかし、彼女は通常小額のお金を送金しており、メッセージの最上位ビットをビットフリップして `0x1110 1011 1101` とすることをイメージします。被害者はメッセージを受け取り、秘密鍵と XOR をとって復号し、3048 ユーロ/ドルの額となる `0x1011 1110 1000` の値を取得しました。攻撃者は暗号化を破ることができませんでしたが、元となるメッセージは完全性が保護されていないため、彼女は元となるメッセージを変更できました。

#### 静的解析

-- TODO --

* 使用されているアルゴリズムについてソースコードを確認します

#### 動的解析

-- TODO [Give examples of Dynamic Testing for "Testing for Insecure and/or Deprecated Cryptographic Algorithms"] --

#### 改善方法

暗号化されたデータを保護する暗号方式は認証付き暗号 <sup>[1]</sup> と呼ばれます。チェックサムの作成に使用される基本プリミティブは MAC (鍵付きハッシュとも呼ばれます) です。どのデータ (プレーンテキストまたは暗号テキスト) を MAC 化するかの正しい選択は非常に複雑です <sup>[2]</sup> 。

暗号化の完全性保護に AES-GCM などの AEAD スキームの使用を推奨します。

#### 参考情報

##### OWASP Mobile Top 10

* M6 - Broken Cryptography

##### OWASP MASVS

- V3.3: "アプリは特定のユースケースに適した暗号化プリミティブを使用している。業界のベストプラクティスに基づくパラメータで構成されている。"

##### CWE

-- TODO --

##### その他

* [1] Wikipedia: Authenticated Encryption -- https://en.wikipedia.org/wiki/Authenticated_encryption
* [2] Luck Thirteen: Breaking the TLS and DTLS Record Protocols -- http://www.isg.rhul.ac.uk/tls/TLStiming.pdf

##### ツール

-- TODO --
