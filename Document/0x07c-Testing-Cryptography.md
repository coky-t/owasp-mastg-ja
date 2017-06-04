## 暗号化のテスト

以下の章では MASVS の暗号化要件の技術的なテストケースを説明します。この章に記載されているテストケースは一般的な暗号の概念に基づいており、iOS や Android の特定の実装に依存していません。

適切な暗号システムの設計はモバイルアプリケーション開発での一般的な落とし穴です。適切なセキュリティを実現するには、開発者は適切な暗号化ディレクティブ (対称暗号化など) を選択し、そのディレクティブに対する適切な実装 (AES-GCM など) を選択し、その実装を正しく設定する (鍵長、ブロックモード、鍵管理など) 必要があります。この章では暗号の説明はしませんが、その質問は前述の選択と実装のプロセスで共通の問題を見つけるように設計されています。

この章では、複数の基本的な暗号化ビルディングブロックが使用されています。以下に一般的に言及されている概念を紹介します。

* ハッシュは元のデータに基づく固定長のチェックサムを迅速に計算するために使用されます。同じ入力データは同じ出力ハッシュを生成します。暗号学的ハッシュは、生成されたハッシュが元のデータについて推論することを制限すること、元のデータ内の小さな変更が完全に異なるハッシュを生成すること、ハッシュを取得して同じハッシュにつながる入力データを提供することが実現可能でないこと、を保証します。秘密鍵は使用されないため、攻撃者はデータが変更された後に新しいハッシュを再計算できます。
* 暗号化は元のプレーンテキストデータを暗号化されたテキストに変換して、その後暗号化されたテキスト (暗号テキストともいいます) から元のデータを再構築することを可能にします。したがってデータの機密性を提供します。
* 対称暗号化は秘密鍵を使用します。暗号化されたデータの機密性は機密鍵の機密性にのみ依存します。これは、秘密鍵は秘密でなければならず、したがって予測可能ではないことを意味します。
* 非対称暗号化は2つの鍵を使用します。プレーンテキストを暗号化するために使用できる公開鍵とプレーンテキストから元のデータを再構築するために使用できる秘密鍵です。

### 暗号のカスタム実装に関するテスト

#### 概要

非標準の暗号アルゴリズムやカスタムビルドの暗号アルゴリズムの使用は危険です。特定の攻撃者がアルゴリズムを破り、保護されているデータを侵害する可能性があります。暗号化機能の実装には時間がかかり、困難であり、失敗する可能性が非常に高くなります。代わりに既にセキュアであることが証明されている既知のアルゴリズムを使用すべきです。すべての成熟したフレームワークやライブラリはモバイルアプリを実装する際にも使用すべき暗号化機能を提供します。

#### 静的解析

ソースコードに含まれるすべての暗号手法、特に機密データに直接適用されている手法を注意深く調べます。一見標準のようにみえるが改変されたアルゴリズムに細心の注意を払います。エンコーディングは暗号化ではないことを忘れないでください。排他的 OR 演算などのビットシフト演算子が現れたら深く掘り下げてみる良い兆候かもしれません。

#### 動的解析

カスタム暗号化方式の使用について、APK を逆コンパイルして得られたソースコードを調べることをお勧めします(「静的解析」を参照ください)。

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
* CRC32
* MD4
* MD5
* SHA1 など

脆弱とみなされている DES アルゴリズムの初期化の例：
```Java
Cipher cipher = Cipher.getInstance("DES");
```

#### 動的解析

カスタム暗号化方式の使用について、APK を逆コンパイルして得られたソースコードを調べることをお勧めします(「静的解析」を参照ください)。

テスト中にローカルに格納されているデータに遭遇した場合には、使用されているアルゴリズムを特定し、既知のセキュアではないアルゴリズムのリストと比較して検証します。

#### 改善方法

暗号化が廃止されたものではないことを定期的に確認します。
かつては何年もの計算時間を要すると考えられていた一部の古いアルゴリズムは、数日または数時間で破られる可能性があります。
これには以前は強力であると考えられていた MD4, MD5, SHA1, DES やその他のアルゴリズムが含まれます。
現在推奨されるアルゴリズムの例です <sup>[1] [2]</sup> ：

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

#### 動的解析

カスタム暗号化方式の使用について、APK を逆コンパイルして得られたソースコードを調べることをお勧めします(「静的解析」を参照ください)。

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

### 安全ではない暗号アルゴリズム設定に関するテスト

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

### ECB モードの使用に関するテスト

#### 概要

その名前が暗示するように、ブロックベースの暗号化は離散入力ブロックに対して実行されます。例えば、AES を使用する場合には 128 ビットのブロックです。プレーンテキストがブロックサイズよりも大きい場合、与えられた入力サイズのブロックに内部的に分割され、各ブロックに対して暗号化が実行されます。一つの暗号化されたブロックの結果がその後に暗号化されるブロックに影響を及ぼす場合、いわゆるブロックモードが定義されます。

ECB (Electronic Codebook) 暗号化モードは使用すべきではありません。基本的に入力を固定サイズのブロックに分割して、各ブロックを個別に暗号化します <sup>[6]</sup> 。例えば、画像が ECB ブロックモードを利用して暗号化されている場合、入力画像は複数の小さなブロックに分割されます。各ブロックは元の画像の小さな領域を表しています。それぞれが同じ秘密の入力鍵を使用して暗号化されます。入力ブロックが類似している場合、例えば入力ブロックが白い背景のみである場合、結果として得られる暗号化された出力ブロックも同じになります。結果として得られる暗号化画像の各ブロックは暗号化されていますが、画像の全体的な構造は結果として得られる暗号化画像内で依然として認識可能です。

![Electronic Codebook (ECB mode encryption)](Images/Chapters/0x07c/ECB.png)

![Difference of encryption modes](Images/Chapters/0x07c/EncryptionMode.png)

#### 静的解析

ソースコードを使用して、使用されているブロックモードを確認します。特に ECB モードについてチェックします。以下に例を示します。

```
Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
```

#### 動的解析

再発するパターンについて暗号化されたデータをテストします。これらは ECB モードが使用されていることを示すものです。

#### 改善方法

カウンターモード (CTR) などの後続するブロックに対するフィードバック機構を提供する確立されたブロックモードを使用します。暗号化されたデータを格納するために、ガロア・カウンターモード (GCM) などの格納されたデータの完全性を付加的に保護するブロックモードを使用することが多くの場合賢明です。後者はアルゴリズムが各 TLSv1.2 の実装に必須であるという追加の利点があります。したがって、すべての最新のプラットフォームで利用っできます。

ブロックモード選択に関する NIST のガイドライン <sup>[1]</sup> を参照ください。

#### 参考情報

##### OWASP Mobile Top 10
* M6 - Broken Cryptography

##### OWASP MASVS
- V3.3: "アプリは特定のユースケースに適した暗号化プリミティブを使用している。業界のベストプラクティスに基づくパラメータで構成されている。"

##### CWE
* CWE-326: Inadequate Encryption Strength
* CWE-327: Use of a Broken or Risky Cryptographic Algorithm

##### その他

- [1] NIST Modes Development, Proposed Modes - http://csrc.nist.gov/groups/ST/toolkit/BCM/modes_development.html
- [6] Electronic Codebook (ECB) - https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_Codebook_.28ECB.29

##### ツール
* QARK - https://github.com/linkedin/qark
* Mobile Security Framework - https://github.com/ajinabraham/Mobile-Security-Framework-MobSF



### Testing if anything but a KDF (key-derivation function) is used for storing passwords

#### Overview

Normal hashes are optimized for speed, e.g., optimized to verify large media in short time. For password storage this property is not desirable as it implies that an attacker can crack retrieved password hashes (using rainbow tables or through brute-force attacks) in a short time. For example, when the insecure MD5 hash has been used, an attacker with access to eight high-level graphics cards can test 200.3 Giga-Hashes per Second<sup>[1]</sup>.

A solution this are Key-Derivation Functions (KDFs) that have a configurable calculation time. While this imposes a larger performance overhead this is negligible during normal operation but prevents brute-force attacks. Recently developed key derivation functions such as Argon2 or scrypt have been hardened against GPU-based password cracking.

#### Static Analysis

Use the source code to determine how the hash is calculated, an exmaple of an insecure instantiation would be:

```
MessageDigest md = MessageDigest.getInstance("MD5");
md.updat("too many secrets");
byte[] digest = md.digest();
```

#### Dynamic Analysis

If hashes were extracted and they have been configured in an insecure manner, a brute-force password cracking tool, e.g. hashcat, can be used to extract the original plain-text passwords from the encrypted hashes. Hashcat's wiki contains examples of cracking speeds for different algorithms, this can be utilized to estimate the effort that an attacker would have to recover plain-text passwords.

To utilize brute-force tools, the used hash algorithm (e.g., MD5 or SHA1) must be known. If this knowledge is not gathered during the Testing, tools like hashID can be used to automatically identify hash algorithms.

#### Remediation

Use an established key derivation function such as PBKDF2 (RFC 2898<sup>[5]</sup>), Argon2<sup>[4]</sup>, bcrypt<sup>[3]</sup> or scrypt (RFC 7914<sup>[2]</sup>).

#### References

##### OWASP Mobile Top 10

* M6 - Broken Cryptography

##### OWASP MASVS

- V3.3: "The app uses cryptographic primitives that are appropriate for the particular use-case, configured with parameters that adhere to industry best practices"
- V3.4: "The app does not use cryptographic protocols or algorithms that are widely considered depreciated for security purposes"

##### CWE

-- TODO --

##### Info

[1] 8x Nvidia GTX 1080 Hashcat Benchmarks -- https://gist.github.com/epixoip/a83d38f412b4737e99bbef804a270c40
[2] The scrypt Password-Based Key Derivation Function -- https://tools.ietf.org/html/rfc7914
[3] A Future-Adaptable Password Scheme -- https://www.usenix.org/legacy/events/usenix99/provos/provos_html/node1.html
[4] https://github.com/p-h-c/phc-winner-argon2
[5] PKCS #5: Password-Based Cryptographic Specification Version 2.0 -- https://tools.ietf.org/html/rfc2898

##### Tools

* hashcat - https://hashcat.net/hashcat/
* hashID - https://pypi.python.org/pypi/hashID

### Test if user-supplied credentials are not directly used as key material

#### Overview

Cryptographic algorithms -- such as symmetric encryption or MACs -- expect a secret input of a a given size, e.g. 128 or 256 bit. A naive implementation might use the use-supplied password directly as an input key. There are a couple of problems with this approach:

* if the password is smaller than the key, then not the full key-space is used (the rest is padded, sometimes even with spaces)
* A user-supplied password will realistically consist mostly of display- and pronounce-able characters. So instead of the full entropy, i.e. 2<sup>8</sup> when using ASCII, only a small subset is (approx. 2<sup>6</sup>) is used.
* If two users select the same password an attacker can match the encrypted files. This opens up the possibility of rainbow table attacks.

#### Static Analysis

Use the source code to verify that no password is directly passed into an encryption function, e.g.:


```
String userKeyString = "trustno1"; // given by user
byte[] userKeyByte = userKeyString.getBytes();
byte[] validKey = new byte[16]; // needed input key, filled with 0

System.arraycopy(userKeyByte, 0, validKey, 0, (userKeyByte.length > 16) ? 16 : userKeyByte.length));

Key theAESKEy = new SecretKeySpec(validKey, "AES");
```

#### Dynamic Analysis

Test extrated hashes as within "Testing if anything but a KDF (key-derivation function) is used for storing passwords". If no hash or KDF has been used, brute-force attacks or attacks using dictionaries will be more efficient due to the reduced key space.

#### Remediation

Pass the user-supplied password into a salted hash funcation or KDF; use its resuls as key for the cryptographic function.

#### References

##### OWASP Mobile Top 10

* M6 - Broken Cryptography

##### OWASP MASVS

- V3.3: "The app uses cryptographic primitives that are appropriate for the particular use-case, configured with parameters that adhere to industry best practices"

##### CWE

-- TODO --

##### Info

* Wikipedia -- https://en.wikipedia.org/wiki/Key_stretching

##### Tools

* hashcat - https://hashcat.net/hashcat/
* hashID - https://pypi.python.org/pypi/hashID

### Test if sensitive data is integrity protected

#### Overview

The attack surface of an application is defined as the sum of all potential input paths. An often forgotten attack vector are files stored on insecure locations, e.g., cloud storage or local file storage.

All data that is stored on potential insecure locations should be integrity protected, i.e., an attacker should not be able to change their content without the application detecting the change prior to the data being used.

Most countermeasures work by calculating a checksum for the stored data, and then by comparing the checksum with the retrieved data prior to the data's import. If the checksum/hash is stored with the data on the insecure location, typical hash algorithms will not be sufficient. As they do not posess a secret key, an attacker that is able to change the stored data, can easily recalculate the hash and store the newly calculated hash.

#### Static Analysis

-- TODO --

* check source code for used algorithm

#### Dynamic Analysis

-- TODO --


#### Remediation

Two typical cryptographic counter-measures for integrity protection are:

* MACs (Message Authentication Codes, also known as keyed hashes) combine hashes with a secret key. The MAC can only be calculated or verified if the secret key is known. In contrast to hashes this means, that an attacker cannot easily calculate a MAC after the original data was modified. This is well suited, if the application can store the secret key within its own storage and no other party needs to verify the authenticity of the data.

* Digital Signatures are a public key-based scheme where, instead of a single secret key, a combination of a secret private key and a a public key is sued. The signature is created utilizing the secret key and can be verified utilizing the public key. Similar to MACs, an attacker cannot easily create a new signature. In contrast to MACs, signatures allow verification without needed to disclose the secret key. Why is not everyone using Signatures instead of MACs? Mostly for performance reasons.

* Another possibility is the usage of encryption using AEAD schemes (see "Test if encryption provides data integrity protection")

#### References

##### OWASP Mobile Top 10

* M6 - Broken Cryptography

##### OWASP MASVS

- V3.3: "The app uses cryptographic primitives that are appropriate for the particular use-case, configured with parameters that adhere to industry best practices"

##### CWE

-- TODO --

##### Info

-- TODO --

##### Tools

-- TODO --


### Test if encryption provides data integrity protection

#### Overview

Please note that, encryption does not provide data integrity, i.e., if an attacker modifies the cipher text and a user decrypts the modified cipher text, the resulting plain-text will be garbage (but the decryption operation itself will perform successfully).

A good example for an symmetric algorithm that does not protect integrity is One-Time-Pad. This algorithm XORs the input data with a secret input key. This leads to a cipher text which's data confidenciality is information theoretical secure -- i.e. even an attacker with unlimited processing power would not be able to crack the encryption. But data integrity is not protected.

For example, image that you have a message with an amount of money to be transfered. Let the amount be 1000 Euro/Dollars, which would be `0x0011 1110 1000` the secret key that you are using is `0x0101 0101 0101` (not very random, I know). XORing those two leads to a transfered message of `0x0110 1011 1101`. The attacker has no idea of knowning the plain-text. But she imagines that normally a low amount of money is transfered and bit-flips the highest bit of the message, making it `0x1110 1011 1101`. The victim now retrieves the message, decrypts it through XORing it with the secret key and has retrieved the value of `0x1011 1110 1000` which amounts to 3048 Euro/Dollars. So while the attacker was not able to break the encryption, she was able to change the undelying message as the underlying message was not integrity protected.

#### Static Analysis

-- TODO --

* check source code for used algorithm

#### Dynamic Analysis

-- TODO [Give examples of Dynamic Testing for "Testing for Insecure and/or Deprecated Cryptographic Algorithms"] --

#### Remediation

The cryptographic method that secures encrypted data is unsurprisingly called Authenticated Encryption<sup>[1]</sup>. The basic primitive used for creating the checksum is a MAC (also known as keyed hash). The exact selection what data is MACed (plain-text or cipher-text) is highly complex<sup>[2]</sup>.

It is recommended to use an AEAD scheme for integrity-protecting encryption such as AES-GCM.

#### References

##### OWASP Mobile Top 10

* M6 - Broken Cryptography

##### OWASP MASVS

- V3.3: "The app uses cryptographic primitives that are appropriate for the particular use-case, configured with parameters that adhere to industry best practices"

##### CWE

-- TODO --

##### Info

* [1] Wikipedia: Authenticated Encryption -- https://en.wikipedia.org/wiki/Authenticated_encryption
* [2] Luck Thirteen: Breaking the TLS and DTLS Record Protocols -- http://www.isg.rhul.ac.uk/tls/TLStiming.pdf

##### Tools

-- TODO --
