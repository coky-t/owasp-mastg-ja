## 暗号化のテスト

### 暗号鍵管理の検証

#### 概要

-- TODO [Provide a general description of the issue "Verifying Cryptographic Key Management"] --

#### 静的解析

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm purpose of remark "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

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

-- TODO [Provide a general description of the issue "Verifying the Configuration of Cryptographic Standard Algorithms"] --

#### 静的解析

Apple は最も一般的に使用される暗号アルゴリズムの実装でのライブラリを提供しています。[Cryptographic Services Guide](https://developer.apple.com/library/content/documentation/Security/Conceptual/cryptoservices/GeneralPurposeCrypto/GeneralPurposeCrypto.html)を参照ください。標準ライブラリを使用して暗号プリミティブを初期化および使用する方法についての広範な文書を含んでいます。ソースコード解析を実行する際にも役立ちます。
ブラックボックステストでは、CommonCryptor などのネイティブ C API がより便利で、暗号操作を実行する際に最も頻繁に使用されます。ソースコードの一部は [opensource.apple.com](https://opensource.apple.com) から入手できます。

##### ソースコードあり

-- TODO [Create content for "Verifying the Configuration of Cryptographic Standard Algorithms" with source code] --

##### ソースコードなし

アプリケーションが Apple により提供される標準的な暗号実装を使用している場合、最も簡単な方法はアプリケーションを逆コンパイルし、`CCCrypt`, `CCCryptorCreate` などの `CommonCryptor` から関数への呼び出しををチェックすることです。[
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

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### ツール

-- TODO [Add links to relevant tools for "Verifying the Configuration of Cryptographic Standard Algorithms"] --
* Enjarify - https://github.com/google/enjarify

### 安全でないもしくは廃止された暗号化プリミティブに関するテスト

#### 概要

-- TODO [Provide a general description of the issue "Testing for Insecure and/or Deprecated Cryptographic Primitives"] --

#### 静的解析

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- [Confirm purpose of remark "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>." ] --

##### ソースコードあり

-- TODO [Add content on "Testing for Insecure and/or Deprecated Cryptographic Primitives"  with source code] --

##### ソースコードなし

-- TODO [Add content on "Testing for Insecure and/or Deprecated Cryptographic Primitives"  without source code] --

#### 動的解析

-- TODO [Describe how to test for this issue "Testing for Insecure and/or Deprecated Cryptographic Primitives" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing for Insecure and/or Deprecated Cryptographic Primitives".] --

#### 参考情報

##### OWASP Mobile Top 10 2014

* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing for Insecure and/or Deprecated Cryptographic Primitives".] --
- VX.Y: "Requirement text, e.g. 'the keyboard cache is disabled on text inputs that process sensitive data'."

##### CWE

-- TODO [Add relevant CWE for "Testing for Insecure and/or Deprecated Cryptographic Primitives"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### その他

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### ツール

-- TODO [Add links to relevant tools for "Testing for Insecure and/or Deprecated Cryptographic Primitives"] --
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
