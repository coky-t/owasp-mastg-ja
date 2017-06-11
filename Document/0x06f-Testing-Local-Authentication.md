## ローカル認証のテスト (iOS アプリ)

MASVS の認証とセッション管理要件のほとんどは汎用的なものであるため、iOS や Android の特定の実装に依存しません。

結果として、要件「4.6 生体認証が使用される場合は（単に「true」や「false」を返すAPIを使うなどの）イベントバインディングは使用しない。代わりに、キーチェーンやキーストアのアンロックに基づくものとする。」だけが本章に記載されています。他のすべてのテストではサーバー側実装を検証する必要があります。付録「認証とセッション管理のテスト」にあります。


### 生体認証のテスト

#### 概要

-- TODO [Provide a general description of the issue "Testing Biometric Authentication".]

#### 静的解析

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm purpose of remark "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

-- TODO [Add content for "Testing Biometric Authentication" with source code] --

#### 動的解析

-- TODO [Describe how to test for this issue "Testing Biometric Authentication" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### 改善方法

Example: https://www.raywenderlich.com/92667/securing-ios-data-keychain-touch-id-1password
-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing Biometric Authentication".] --

#### 参考情報

##### OWASP Mobile Top 10 2016
* M4 - 安全でない認証 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS
* 4.6: "生体認証が使用される場合は（単に「true」や「false」を返すAPIを使うなどの）イベントバインディングは使用しない。代わりに、キーチェーンやキーストアのアンロックに基づくものとする。"

##### CWE

-- TODO [Add relevant CWE for "Testing Biometric Authentication"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### その他

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### ツール

-- TODO [Add relevant tools for "Testing Biometric Authentication"] --
* Enjarify - https://github.com/google/enjarify
