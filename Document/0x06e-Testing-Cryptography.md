## 暗号化のテスト

### 暗号鍵管理の検証

#### 概要

適切な暗号鍵管理は多くの場合モバイルアプリケーションの落とし穴のひとつです。プラットフォームはキーチェーンなどの標準的なシステム API を提供していますが、往々にして開発者はまったく使用しないか不適切に使用しています。

#### 静的解析

静的解析の中で最も重要な部分は、アプリケーションが暗号アルゴリズムをどのように使用しているかを理解することです。アプリケーションを3つの主要なカテゴリに分けてみます。

1. アプリケーションは純粋なオンラインアプリケーションです。認証、認可はアプリケーションサーバーとオンラインで行われます。情報はローカルに格納されません。
2. アプリケーションは主にオフラインアプリケーションです。認証、認可は純粋にローカルで行われます。アプリケーション情報はローカルにも格納されます。
3. アプリケーションは最初の2つが混在しています。すなわち、オンライン認証とオフライン認証の両方をサポートし、一部の情報はローカルに格納される可能性があり、オンラインで実行されるアクションの一部またはすべてがオフラインで実行される可能性があります。
   * このようなアプリケーションの良い例として売り手が商品を販売する店頭 POS があります。   このアプリはバックエンドと通信して販売された商品、現金額などの情報を更新できるようインターネットに接続する必要があります。   但し、このアプリはオフラインモードでも動作する必要があり、インターネットに接続するとすべての情報を同期するというビジネス要件があるかもしれません。   これはオンラインとオフラインが混在するアプリタイプです。
   
両方のアプリケーションで以下のチェックを実行します。
* ソースコード内に鍵/パスワードが格納されていないことを確認します。ソースコードで有効になっている「管理者」アカウントやバックドアアカウントには特に注意します。アプリケーションやパスワードハッシュ内に固定ソルトを格納すると問題が発生する可能性があります。
* ソースコード内に難読化された鍵やパスワードがないことを確認します。難読化は動的計装によって簡単にバイパスされますので、原理的にハードコードされた鍵と変わりません。
* アプリケーションが双方向 SSL を使用している(すなわち、サーバー証明書とクライアント証明書の両方が検証されている)場合、以下のことを確認します。
   * クライアント証明書のパスワードがローカルに格納されていないこと。キーチェーンに格納する必要があります。
   * クライアント証明書がすべてのインストールで共有されていないこと(アプリ内でハードコードされているなど)
   
   適切な方法は、ユーザー登録/初回ログイン時にクライアント証明書を生成してそれをキーチェーンに格納することです。
* 鍵/パスワード/ログインがアプリケーションデータに格納されていないことを確認します。これには iTunes バックアップを含めることができ、攻撃領域を拡大することができます。キーチェーンはあらゆる種類の資格情報(パスワード、証明書など)を格納する唯一の場所です。
* キーチェーンエントリに適切な保護クラスがあることを確認します。最も厳密なのは `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` で次のように解釈されます。デバイスのパスコードが設定され、デバイスがロックされていない場合にのみエントリが解除されます。そのエントリはバックアップやその他の手段でエクスポートできません。

オフラインアプリケーションでは以下のチェックを実行します。
* アプリがアプリデータに格納されている追加の暗号化コンテナに依存している場合は、暗号鍵の使用方法を確認します。
   * 鍵ラッピングスキームが使用されている場合は、マスターシークレットがユーザーごとに初期化されているか、コンテナが新しい鍵で再暗号化されていることを確認します。
   * マスターシークレットや以前のパスワードを使用してコンテナを復号化できる場合は、パスワード変更がどのように処理されるかを確認します。
   

##### ソースコードあり

-- TODO [Create content of ""Verifying Cryptographic Key Management" with source code] --

##### ソースコードなし

-- TODO [Create content of "Verifying Cryptographic Key Management" without source code] --

#### 動的解析

-- TODO [Describe how to test for this issue "Verifying Cryptographic Key Management" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue "Verifying Cryptographic Key Management".] --

#### 参考情報

##### OWASP Mobile Top 10 2014

* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

-- TODO [Update below reference "VX.Y" for "Verifying Cryptographic Key Management"] --
- VX.Y: "Requirement text, e.g. 'the keyboard cache is disabled on text inputs that process sensitive data'."

##### CWE

-- TODO [Add relevant CWE for "Verifying Cryptographic Key Management"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### その他

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### ツール

-- TODO [Add link to relevant tools for "Verifying Cryptographic Key Management"] --
* Enjarify - https://github.com/google/enjarify


### 暗号のカスタム実装に関するテスト

#### 概要

非標準アルゴリズムの使用は危険です。果敢な攻撃者がアルゴリズムを破り、データが保護されていても漏洩してしまうためです。アルゴリズムを破る既知の技法が存在する可能性があります。

#### ホワイトボックステスト

すべての暗号手法、特に機密データに直接適用されている手法を注意深く調べます。一見標準のようにみえるが改変されたアルゴリズムに細心の注意を払います。エンコーディングは暗号化ではないことを忘れないでください。直接的な XOR が現れたら深く掘り下げてみる良い兆候かもしれません。

#### ブラックボックステスト

非常に弱い暗号の場合はカスタムアルゴリズムのファジングが機能するかもしれませんが、カスタム暗号化方式が本当に適切かどうか確認するために、アプリを逆コンパイルしてアルゴリズムを調べることをお勧めします(「ホワイトボックステスト」を参照ください)。

#### 改善方法

機密データを格納もしくは転送する必要がある場合は、強力な最新の暗号アルゴリズムを使用してそのデータを暗号化します。この分野の専門家により現在強力であるとみなされている十分に検証されたアルゴリズムを選択し、十分にテストされた実装を使用します。すべての暗号化機能と同様に、解析にはソースコードが利用可能であるべきです。
カスタムもしくはプライベートの暗号アルゴリズムを開発してはいけません。それらは暗号技術者によってよく知られている攻撃にさらされる可能性があります。リバースエンジニアリング技法は成熟しています。アルゴリズムが漏洩し、攻撃者がどのように動作するか分かったとき、特に脆弱となります。

##### OWASP MASVS

- V3.2: "アプリは実績のある暗号プリミティブの実装を使用している。"

##### OWASP Mobile Top 10

* M6 - Broken Cryptography

##### CWE

* CWE-327: Use of a Broken or Risky Cryptographic Algorithm

### 暗号化標準アルゴリズムの構成の検証

#### 概要

Apple provides libraries with implementations of most commonly used cryptographic algorithms. A good point of reference is Apple's  Cryptographic Services Guide <sup>[1]</sup>. It contains broad documentation on how to use standard libraries to initialize and use cryptographic primitives, which is also useful when performing source code analysis. 
For black-box testing, more useful is native C API, for instance CommonCryptor, that is most frequently used when performing cryptographic operations. Source code is partially available at the Apple open source repository <sup>[2]</sup>.

#### 静的解析

The main goal of static analysis is to ensure the following:

* cryptographic algorithms are up to date and in-line with industry standards. This includes, but is not limited to outdated block ciphers (e.g. DES), stream ciphers (e.g. RC4), as well as hash functions (e.g. MD5), crooked random number generators like Dual_EC_DRBG (even if they are NIST certified). All of these should be marked as insecure and removed from the application or server.
* key lengths are in-line with industry standards and provide protection for sufficient amount of time. An online comparison of different key lenghts and protection they provide taking into account Moore's law is available on the web <sup>[3]</sup>.
* cryptographic parameters are well defined within reasonable range. This includes, but is not limited to: cryptographic salt, which should be at least the same length as hash function output, reasonable choice of password derivation function and iteration count (e.g. PBKDF2, scrypt or bcrypt), IVs being random and unique, fit-for-purpose block encryption modes (e.g. ECB should not be used, except specific cases), key management being done properly (e.g. 3DES should have three independent keys) and so on.

##### ソースコードあり

-- TODO [Create content for "Verifying the Configuration of Cryptographic Standard Algorithms" with source code] --

##### ソースコードなし

アプリが Apple により提供される標準的な暗号実装を使用している場合、最も簡単な方法はアプリケーションを逆コンパイルし、`CCCrypt`, `CCCryptorCreate` などの `CommonCryptor` から関数への呼び出しををチェックすることです。[
例えば、`CCCryptorCreate` は以下のシグネチャを持っています。
```
CCCryptorStatus CCCryptorCreate(
	CCOperation op,             /* kCCEncrypt, etc. */
	CCAlgorithm alg,            /* kCCAlgorithmDES, etc. */
	CCOptions options,          /* kCCOptionPKCS7Padding, etc. */
	const void *key,            /* raw key material */
	size_t keyLength,	
	const void *iv,             /* optional initialization vector */
	CCCryptorRef *cryptorRef);  /* RETURNED */
```

すべての `enum` 型を比較して、どのアルゴリズム、パディング、鍵マテリアルが使用されているかを理解することができます。(悪い)パスワードが直接入力された場合や、鍵生成機能(PBKDF2など)から入力された場合は、鍵マテリアルに注意します。
明らかに、アプリケーションが使用している可能性がある他の非標準のライブラリ(`openssl`など)がある場合、それらもチェックします。

#### 動的解析

-- TODO [Describe how to test for this issue "Verifying the Configuration of Cryptographic Standard Algorithms" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue "Verifying the Configuration of Cryptographic Standard Algorithms".] --

#### 参考情報

##### OWASP Mobile Top 10 2014

* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

-- TODO [Update reference below "VX.Y" for "Verifying the Configuration of Cryptographic Standard Algorithms"] --
- VX.Y: "Requirement text, e.g. 'the keyboard cache is disabled on text inputs that process sensitive data'."

##### CWE

-- TODO [Add relevant CWE for "Verifying the Configuration of Cryptographic Standard Algorithms"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### その他

- [1] Apple Cryptographic Services Guide - https://developer.apple.com/library/content/documentation/Security/Conceptual/cryptoservices/GeneralPurposeCrypto/GeneralPurposeCrypto.html
- [2] Apple Open Source - https://opensource.apple.com
- [3] Keylength comparison - https://www.keylength.com/

##### ツール

-- TODO [Add links to relevant tools for "Verifying the Configuration of Cryptographic Standard Algorithms"] --
* Enjarify - https://github.com/google/enjarify


### 乱数生成器のテスト

#### 概要

-- TODO [Provide a general description of the issue "Testing Random Number Generation".] --

#### 静的解析

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- [Confirm purpose of remark "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

##### ソースコードあり

-- TODO [Add content for "Testing Random Number Generation" with source code] --

##### ソースコードなし

-- TODO [Add content for "Testing Random Number Generation" without source code] --

#### 動的解析

-- TODO [Describe how to test for this issue "Testing Random Number Generation" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing Random Number Generation".] --

#### 参考情報

##### OWASP Mobile Top 10 2014

* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

-- TODO [Update reference below "VX.Y" for "Testing Random Number Generation"] --
- VX.Y: "Requirement text, e.g. 'the keyboard cache is disabled on text inputs that process sensitive data'."

##### CWE

-- TODO [Add relevant CWE for "Testing Random Number Generation"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### その他

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### ツール

-- TODO [Add links to relavant tools for "Testing Random Number Generation"] --
* Enjarify - https://github.com/google/enjarify
