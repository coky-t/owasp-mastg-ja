## リモート認証と認可

以下の章ではテクニカルテストケースでの MASVS の認証とセッション管理要件について説明します。この章に記載されるテストケースはサーバー側に焦点を当てているため、iOS や Android の特定の実装に依存しません。

以下のすべてのテストケースでは、まずどのような種類の認証メカニズムが使用されているかを調べる必要があります。サーバー側認証を実装するには、以下のいずれかの方法が利用できます。
* クッキーベースの認証
* トークンベースの認証

クッキーベースの認証は Web アプリケーションで使用される従来の認証メカニズムです。モバイルアプリのさまざまな要件に対応するため、トークンベースの認証が指定され、今日ではモバイルアプリでますます使用されています。これの顕著な例は OAuth2 認証および認可のフレームワークである JSON Web Token または JWT <sup>[1]</sup> です。


### ユーザーが正しく認証されていることの検証

#### 概要

アプリケーションは、一方では公的で非特権的な情報や機能、他方で機密性が高く特権的な情報や機能といったさまざまなエリアを有することがよくあります。ユーザーは前者に制限なしで合法的にアクセスできます。しかし、機密性が高く特権的な情報や機能は正当なユーザーだけに保護されアクセスできるようにするために、適切な認証が行われる必要があります。

認証は常にサーバー側コードで処理する必要があり、クライアント側のコントロールに頼るべきではありません。ユーザーのワークフローを改善するために、クライアント側のコントロールを使用して特定のアクションのみを許可することはできますが、ユーザーがアクセスできるものを定義するサーバー側の対応が常に必要です。

JWT によるトークンベースの認証が使用される場合は、「JSON Web Token (JWT) のテスト」も参照ください。

#### 静的解析

サーバー側ソースコードが入手可能である場合は、まずサーバー側で使用および実施されている認証メカニズム(トークンまたはクッキーベース)を特定します。それから機密性が高く特権的な情報や機能を持つすべてのエンドポイントを突き止めます。それらは保護する必要があるものです。アイテムにアクセスする前に、アプリケーションはユーザーが実際に誰でありエンドポイントにアクセスすることを許可されていることを確認する必要があります。ユーザーを認証したり既存のセッショントークンを取得およびチェックするために使用されるサーバーソースコードのキーワードを探します。

認証メカニズムはゼロから実装するのではなく、この機能を提供するフレームワーク上に構築すべきです。サーバー側で使用されるフレームワークを特定し、利用可能な認証 API や関数を使用してベストプラクティスに応じて使用されるかどうか検証すべきです。サーバー側で広く使用されるフレームワークは以下のとおりです。

- Spring (Java) - https://projects.spring.io/spring-security/
- Struts (Java) - https://struts.apache.org/docs/
- Laravel (PHP) - https://laravel.com/docs/5.4/authentication
- Ruby on Rails -  http://guides.rubyonrails.org/security.html

#### 動的解析

認証を検証するには、まずユーザーがアプリ内でアクセスできるすべての特権エンドポイントを調べるべきです。エンドポイントに送信されるすべてのリクエストに対して、傍受プロキシを使用して認証されている間のネットワークトラフィックを取得します。次に、認証情報を削除してリクエストの再生を試みます。エンドポイントが依然としてリクエストされたデータを送り返している場合、認証されたユーザーにのみ利用可能にすべきであり、認証チェックがエンドポイントで正しく実装されていません。

さらなる攻撃方法については Web ベースアプリケーションに関する OWASP テストガイド V4 (OTG-AUTHN-004) <sup>[3]</sup> にあります。また、OWASP テストガイド <sup>[2]</sup> には多くの認証についてのテストケースがあります。

#### 改善方法

保護が必要なセクションごとに、ユーザーのセッショントークンをチェックするメカニズムを実装します。
- セッショントークンがない場合、ユーザーは以前に認証されていない可能性があります。
- トークンが存在する場合、このトークンが有効であり、ユーザーがそのセクションにアクセスするのに十分な特権を付与されることを確認します。

これらの2つの条件のいずれかが問題を引き起こす場合、リクエストを拒否して、ユーザーがアクティビティを開始できないようにします。

#### 参考情報

##### OWASP Mobile Top 10 2016

* M4 - 安全でない認証 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS

- 4.1: "アプリがリモートサービスへのアクセスを提供する場合、ユーザー名/パスワード認証など許容される形態の認証がリモートエンドポイントで実行されている。"

##### CWE

- CWE-287: Improper Authentication - https://cwe.mitre.org/data/definitions/287.html

##### その他

[1] OWASP JWT Cheat Sheet for Java: `https://www.owasp.org/index.php/JSON_Web_Token_(JWT)_Cheat_Sheet_for_Java`
[2] OWASP Testing Guide V4 (Testing for Session Management) - https://www.owasp.org/index.php/Testing_for_Session_Management
[3] OWASP Testing Guide V4 (OTG-AUTHN-004) - https://www.owasp.org/index.php/Testing_for_Bypassing_Authentication_Schema_(OTG-AUTHN-004)


### JSON Web Token (JWT) のテスト

#### 概要

標準 RFC 7519 では JSON Web Token (JWT) が定義されています。JWT は二者間の JSON オブジェクト内の情報の完全性とセキュアな転送を保証します。モバイルアプリでは、メッセージの送信者と受信者の双方を認証することがますます増えています。

エンコードされた JSON Web Token の例が以下にあります <sup>[5]</sup> 。

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ
```

JWT は Base-64 でエンコードされ、三つの部分に分かれています。

* **ヘッダー** アルゴリズムとトークンタイプ (eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9):
```JSON
{"alg":"HS256","typ":"JWT"}
```
* **ペイロード** データ  (eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9):
```JSON
{"sub":"1234567890","name":"John Doe","admin":true}
```
* **検証署名** (TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ):
```JSON
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  secret
)
```

JWT の実装は PHP <sup>[1]</sup> や Java Spring <sup>[2]</sup> などのすべての主要なプログラミング言語で利用できます。

#### 静的解析

[Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.]

[Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>.]


#### 動的解析

動的解析を実行する中で、いくつかの既知の脆弱性をチェックできます。
* NONE ハッシュアルゴリズム
  *
* クライアント側のトークンストレージ
  * JWT を使用するモバイルアプリを使用する場合、トークンがデバイス上のローカルに格納されている場所を確認する必要があります <sup>[5]</sup> 。


#### 改善方法

ブラウザの sessionStorage コンテナを使用して JWT を保存し、サービスを呼び出すときにそれを Bearer として JavaScript とともに追加します。
JWT を使用している場合は、OWASP JWT Cheat Sheet <sup>[1]</sup> のテストケースにも従ってください。

#### 参考情報

##### OWASP Mobile Top 10 2016

* M4 - 安全でない認証 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS

- 4.1: "アプリがリモートサービスへのアクセスを提供する場合、ユーザー名/パスワード認証など許容される形態の認証がリモートエンドポイントで実行されている。"

##### CWE

- CWE-287: Improper Authentication - https://cwe.mitre.org/data/definitions/287.html

##### その他

* [1] RFC 7519 JSON Web Token (JWT) - https://tools.ietf.org/html/rfc7519
* [2] PHP JWT - https://github.com/firebase/php-jwt
* [3] Java Spring with JWT - http://projects.spring.io/spring-security-oauth/docs/oauth2.html
* [4] OWASP JWT Cheat Sheet - `https://www.owasp.org/index.php/JSON_Web_Token_(JWT)_Cheat_Sheet_for_Java`
* [5] Sample of JWT Token - https://jwt.io/#debugger


### セッション管理のテスト

#### 概要

すべての重要な(権限を持たないかもしれない)アクションはユーザーが適切に認証された後に実行する必要があります。アプリケーションはセッション内でユーザーを覚えています。不適切に管理されると、セッションはさまざまな攻撃の対象となります。正当なユーザーのセッションが悪用され、攻撃者がユーザーを偽装する可能性があります。その結果、データは失われたり、機密性が損なわれたり、不正行為が行われたりする可能性があります。

セッションには開始と終了が必要です。攻撃者がセッショントークンを偽造できないようにする必要があります。代わりに、セッションがサーバー側のシステムによってのみ開始できることを保証する必要があります。また、セッションの継続期間はできる限り短くする必要があり、セッションは一定時間経過後またはユーザーが明示的にログアウトした後に適切に終了する必要があります。セッショントークンを再利用できないようにする必要があります。

したがって、このテストのスコープはセッションがセキュアに管理され、攻撃者により侵害されないことを検証することです。

#### 静的解析

サーバーソースコードが入手可能である場合、テスト担当者はセッションが開始、保存、交換、検証、終了される場所を探します。これは特権情報や特権アクションへのアクセスが発生するたびに実行する必要があります。これらの事項について、自動ツールや手動検索を使用して、対象プログラミング言語に関連するキーワードを探すことができます。サーバー側のフレームワークの例を以下に示します。

- Spring (Java) - http://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/#ns-session-mgmt
- PHP - http://php.net/manual/en/book.session.php
- Ruby on Rails -  http://guides.rubyonrails.org/security.html

#### 動的解析

ベストプラクティスはまず手動もしくは自動ツールを使用してアプリケーションをクロールすることです。目的は、特権情報や特権アクションにつながるアプリケーションのすべての部分が保護され、有効なセッショントークンを必須としているかどうかを確認することです。

次に、任意の傍受プロキシ内でクロールしたリクエストを使用して、セッショントークンの操作を試みます。
- 不正なものに変更する(有効なセッショントークンに 1 を加える、その一部を削除するなど)。
- リクエストの有効なものを削除して、アプリケーションの情報や機能にまだアクセスできるかどうかをテストする。
- ログアウトと再ログインを行い、セッショントークンが変更されているか否かを確認する。
- 特権レベルを変更(ステップアップ認証)する場合。前のものを使用して(つまり低い認可レベルで)アプリケーションの特権部分にアクセスを試みる。
- ログアウト後にセッショントークンの再使用を試みる。

セッション管理テストケースについては OWASP Testing Guide <sup>[1]</sup> も参照ください。

#### 改善方法

前述の攻撃に対して適切な保護を提供するには、セッショントークンを以下のようにする必要があります。
- 常にサーバー側で作成する
- 予測できないようにする (適切な長さとエントロピーを使用する)
- 常にセキュアな接続(HTTPS など)を介してクライアントとサーバー間で交換する
- モバイルアプリ内でセキュアに格納する
- ユーザーがアプリケーションの特権部分にアクセスしようとする際には、(セッショントークンが有効であり、適切な認可レベルに応じていることを)検証する
- ユーザーがより高い特権を必要とする操作を実行するために再度ログインするよう求められた際には、更新する
- ユーザーがログアウトしたとき、もしくは一定時間が経過した後には、サーバー側で終了して、モバイルアプリ内で削除する

使用するフレームワークに組み込まれているセッショントークンジェネレータを使用することを強くお勧めします。それらはカスタムなものを構築するよりもセキュアです。そのようなジェネレータはほとんどのプラットフォームや言語に存在します。

#### 参考情報

##### OWASP Mobile Top 10 2016

* M4 - 安全でない認証 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS

* 4.2: "リモートエンドポイントはランダムに生成されたアクセストークンを使用し、ユーザーの資格情報を送信せずにクライアント要求を認証している。"

##### CWE

- CWE-613 - Insufficient Session Expiration https://cwe.mitre.org/data/definitions/613.html

##### その他

[1] OWASP Testing Guide V4 (Testing for Session Management) - https://www.owasp.org/index.php/Testing_for_Session_Management

##### ツール

* Zed Attack Proxy
* Burp Suite



### ログアウト機能のテスト

#### 概要

セッションの終了はセッションのライフサイクルの重要な部分です。セッショントークンの寿命を最小限にすることはセッションハイジャック攻撃の成功の可能性を低下させます。このテストケースのスコープはアプリケーションにログアウト機能があることおよびクライアント側とサーバー側でセッションを実際に終了させることを検証することです。

##### 静的解析

サーバー側コードが利用可能な場合、ログアウト機能の一部としてセッションが終了していることをレビューします。ここで必要なチェックは使用される技術により異なります。サーバー側で適切なログアウトを実装するためにセッションを終了する方法の例を以下の示します。
- Spring (Java) -  http://docs.spring.io/spring-security/site/docs/current/apidocs/org/springframework/security/web/authentication/logout/SecurityContextLogoutHandler.html
- Ruby on Rails -  http://guides.rubyonrails.org/security.html
- PHP - http://php.net/manual/en/function.session-destroy.php
- JSF - http://jsfcentral.com/listings/A20158?link
- ASP.Net - https://msdn.microsoft.com/en-us/library/ms524798(v=vs.90).aspx

#### 動的解析

アプリケーションを動的に解析するには、傍受プロキシを使用する必要があります。ログアウトが適切に実装されているかどうかを確認するには、以下の手順を実行します。
1.  アプリケーションにログインします。
2.  アプリケーション内で認証に必要な操作を行います。
3.  ログアウト操作を行います。
4.  傍受プロキシを使用して手順2で説明した操作の一つを再送信します。例えば、Burp Repeater を使用します。この目的は手順3で無効にされたトークンを使用してサーバーにリクエストを送信することです。

セッションがサーバー側で正しく終了している場合は、エラーメッセージまたはログインページへのリダイレクトがクライアントに戻されます。そうではなく、手順2で同じレスポンスがある場合、このセッションはまだ有効でありサーバー側で正しく終了していません。
より多くのテストケースを含む詳細な説明は、OWASP Web Testing Guide (OTG-SESS-006) <sup>[1]</sup> にあります。

#### 改善方法

ログアウト機能を実装する際に最もよくあるエラーの一つはサーバー側でセッションオブジェクトを破棄しないことです。これによりユーザーがアプリケーションからログアウトしても、セッションがまだ生きている状態になります。セッションが生き残っていて、攻撃者が有効なセッションを所有していれば、それを引き続き使用することができます。セッションタイムアウトコントロールがなければ、ユーザーはログアウトにより自分自身を保護することさえできません。

これを軽減するには、ログアウトした直後にサーバー側のログアウト機能でこのセッション識別子を無効にして、傍受した可能性のある攻撃者が再利用できないようにする必要があります。

これに関連して、有効期限が切れたトークンで操作を呼び出した後、アプリケーションが別の有効なトークンを生成しないことを確認する必要があります。これにより別の認証バイパスが発生する可能性があります。

多くのモバイルアプリはお客様の利便性のために自動的にはユーザーをログアウトしません。ユーザーは一度ログインすると、サーバー側でトークンが生成され、アプリケーションの内部ストレージに格納されます。アプリケーションの起動時にユーザー資格情報を再度要求することなく、認証に使用されます。トークンが期限切れになるとリフレッシュトークンを使用して (OAuth2/JWT)、ユーザーのセッションを透過的に再開することができます。アプリケーション内にログアウト機能が必要であり、ベストプラクティスに従ってサーバー側のセッションを破棄することで機能します。

#### 参考情報

##### OWASP Mobile Top 10 2016
* M4 - 安全でない認証 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS
-- TODO [Update reference "VX.Y" below for "Testing the Logout Functionality"] --
- 4.3: "ユーザーがログアウトする場合に、リモートエンドポイントは既存のセッションを終了している。"

##### CWE

-- TODO [Add relevant CWE for "Testing the Logout Functionality"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### その他

* [1] OTG-SESS-006 - https://www.owasp.org/index.php/Testing_for_logout_functionality
* [2] Session Management Cheat Sheet - https://www.owasp.org/index.php/Session_Management_Cheat_Sheet



### パスワードポリシーのテスト

#### 概要

パスワードの強度は認証にパスワードを使用する場合の重要な問題です。パスワードポリシーはエンドユーザーが遵守すべき要件を定義します。パスワードの長さ、パスワードの複雑さ、パスワードの形態はパスワードぽりいしーに正しく含まれているべきです。「強力な」パスワードポリシーは手動または自動のいずれかの方法でパスワードを推測することを困難もしくは不可能にさえします。


#### 静的解析

正規表現はパスワードの検証によく使用されます。定義されたパスワードポリシーに対するパスワード検証チェックではパスワードポリシーに違反するパスワードを拒否するかどうかをレビューする必要があります。

アカウントの登録、パスワードの変更、パスワードを忘れた場合のパスワードのリセット時にパスワードを設定できます。アプリケーション内で利用可能なすべてのメカニズムはパスワードポリシーに沿って同じパスワード検証チェックを使用する必要があります。

フレームワークを使用してアプリケーションのすべてのユーザーにパスワードポリシーを作成および強制している場合、公正を確認すべきです。


#### 動的解析

ユーザーがパスワードを設定できるようにするすべての機能は、パスワードポリシー仕様に違反するパスワードを使用できるかどうかを検証する必要があります。これは以下のようになります。

- パスワードを指定できる新規ユーザーの自己登録機能
- ユーザーが新しいパスワードを設定できるパスワード忘れ機能
- ログインユーザーが新しいパスワードを設定できるパスワード変更機能

傍受プロキシを使用して、アプリ内でのローカルパスワードチェックをバイパスし、サーバー側で実装されたパスワードポリシーを検証できるようにします。


#### 改善方法

適切なパスワードポリシーには以下の要件を定義して、パスワード推測攻撃やブルートフォース攻撃を避けるべきでる。

##### パスワードの長さ
* パスワードの最小の長さは少なくとも10文字以上とすべきです。
* パスワードの最大の長さは低すぎてはいけません。ユーザーがパスフレーズを作成する妨げになります。典型的な最大長は128文字です。

##### パスワードの複雑さ
* パスワードは以下の複雑さのルールのうち少なくとも3つを満たす必要があります。
1. 少なくとも1つの英大文字 (A-Z)
2. 少なくとも1つの英小文字 (a-z)
3. 少なくとも1つの数字 (0-9)
4. 少なくとも1つの特殊文字 (記号)

詳細は OWASP Authentication Cheat Sheet <sup>[1]</sup> を参照ください。

#### 参考情報

##### OWASP Mobile Top 10 2016
* M4 - 安全でない認証 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS
* 4.4: "パスワードポリシーが存在し、リモートエンドポイントで実施されている。"

##### CWE
- CWE-521 - Weak Password Requirements

##### その他
* [1] OWASP Authentication Cheat Sheet - https://www.owasp.org/index.php/Authentication_Cheat_Sheet#Implement_Proper_Password_Strength_Controls
* [2] OWASP Testing Guide (OTG-AUTHN-007) - https://www.owasp.org/index.php/Testing_for_Weak_password_policy_(OTG-AUTHN-007)


### 過度なログイン試行のテスト

#### 概要

私たちは皆ブルートフォース攻撃について聞いたことがあります。これは最もシンプルな攻撃タイプの一つです。すでに多くのツールが用意されており、すぐに使用できます。また、ターゲットの深い技術的な理解は必要ありません。ユーザー名とパスワードの組み合わせのリストだけで十分に攻撃を実行できます。有効な資格情報の組み合わせが特定されるとアプリケーションへのアクセスが可能となり、アカウントが侵害される可能性があります。

この種の攻撃から保護するために、アプリケーションは定義された数の不正なログイン試行後にアクセスをブロックするコントロールを実装する必要があります。

保護したいアプリケーションによって、許可される不正な試行回数が異なります。例えば、銀行業務アプリケーションでは3回から5回程度の試行ですが、一般公開のフォーラムではもっと多くの回数となります。この閾値に達するとき、アカウントがロックされるのは永続的か一時的かを決定する必要もあります。アカウントを一時的にロックすることをログイン抑制とも呼びます。

テストはアカウントロックアウトを引き起こす定義された試行回数だけパスワードを誤って入力することにより行われます。その時点で、アンチブルートフォースコントロールが有効になり、正しい資格情報が入力されてもログインは拒否される必要があります。

#### 静的解析

ユーザー名に対する試行回数が設定された試行の最大数に等しいかどうかを確認する検証メソッドがログイン時に存在することを確認する必要があります。この場合、一度この閾値を満たしたら、ログインを許可してはいけません。正しい試行の後、エラーカウンタをゼロに設置する仕組みも必要です。


#### 動的解析

アプリケーションを動的に解析するには傍受プロキシを使用する必要があります。ロックアウトメカニズムが適切に実装されているかどうかを確認するには以下の手順を実行します。
1.  ロックアウトコントロールを引き起こす回数分の間違ったログインをします(一般に3回から15回の間違った試行です)
2.  アカウントをロックアウトしたら、正しいログイン詳細を入力してログインが可能ではないかどうかを確認します。
正しく実装されている場合、正しいパスワードが入力されても資格情報はすでにブロックされているため、ログオンを拒否する必要があります。

#### 改善方法

ブルートフォース攻撃を防ぐためにロックアウトコントロールをサーバー側で実装する必要があります。さらなる軽減技術について OWASP により Blocking Brute Force Attacks <sup>[3]</sup> に記されています。
不正なログイン試行が累積され、セッションにリンクされないことを明確にすることは重要です。同じセッションでの3回目の試行で資格情報をブロックするコントロールを実装すると、間違った情報を2回入力してから新しいセッションを取得することで簡単にバイパスできます。これによりさらに2回のフリーな試行が可能です。

アカウントをロックする代わりにすべてのアカウントに二要素認証 (2FA) か CAPTCHAS の使用を強制します。OWASP Automated Thread Handbook <sup>[4]</sup> の Credential Cracking OAT-007 も参照ください。

#### 参考情報

##### OWASP Mobile Top 10 2016
* M4 - 安全でない認証 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS
* 4.5: "不正な認証資格情報が過度に送信される場合、リモートエンドポイントはExponential Backoffを実装しているか一時的にユーザーアカウントをロックしている。"

##### CWE

-- TODO [Add relevant CWE for "Testing Excessive Login Attempts"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### その他
* [1] OTG-AUTHN-003 - https://www.owasp.org/index.php/Testing_for_Weak_lock_out_mechanism
* [2] Brute Force Attacks - https://www.owasp.org/index.php/Brute_force_attack
* [3] Blocking Brute Force Attacks - https://www.owasp.org/index.php/Blocking_Brute_Force_Attacks
* [4] OWASP Automated Threats to Web Applications - https://www.owasp.org/index.php/OWASP_Automated_Threats_to_Web_Applications

##### ツール
* Burp Suite Professional - https://portswigger.net/burp/
* OWASP ZAP - https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project



### セッションタイムアウトのテスト

#### 概要

Web アプリケーションと比較すると、ほとんどのモバイルアプリケーションには一定時間の非アクティブの後セッションを終了してユーザーに再度ログインを強制するセッションタイムアウトメカニズムがありません。ほとんどのモバイルアプリケーションではユーザーは一度だけ資格情報を入力する必要があります。サーバー側で認証された後、アクセストークンはデバイスに格納され、認証に使用されます。トークンが期限切れになると資格情報を再度入力することなしに透過的にトークンは更新されます (OAuth2 や JWT など) 。診療データのような機密情報や金融取引のような重要な機能を扱うアプリケーションではセッションタイムアウトを実装する必要があります。セキュリティ多層対策として定義された時間後にユーザーに再ログインを強制します。

ここではこのコントロールがクライアント側とサーバー側の両方で正しく実装されていることを確認する方法を説明します。

#### 静的解析

サーバー側コードが使用可能な場合、セッションタイムアウト機能が正しく構成され、定義された時間が経過するとタイムアウトが発生することをレビューすべきです。
ここで必要なチェックは使用する技術により異なります。セッションタイムアウトを構成する方法の例を以下に示します。
- Spring (Java) - http://docs.spring.io/spring-session/docs/current/reference/html5/
- Ruby on Rails -  https://github.com/rails/rails/blob/318a20c140de57a7d5f820753c82258a3696c465/railties/lib/rails/application/configuration.rb#L130
- PHP - http://php.net/manual/en/session.configuration.php#ini.session.gc-maxlifetime
- ASP.Net - https://msdn.microsoft.com/en-GB/library/system.web.sessionstate.httpsessionstate.timeout(v=vs.110).aspx
- Amazon AWS - http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/config-idle-timeout.html


#### 動的解析

動的解析は効率的な選択肢です。セッションタイムアウトが実行時に有効かどうかを傍受プロキシを使用して検証することは簡単です。これはテストケース「ログアウト機能のテスト」に似ていますが、タイムアウト機能をトリガーするために必要な時間分、アプリケーションをアイドル状態のままにする必要があります。この条件を満たしたら、セッションが実際にクライアント側とサーバー側で終了することを検証する必要があります。

セッションタイムアウトが適切に実装されているかどうかを確認するには以下の手順を実行します。
-   アプリケーションにログインします。
-   アプリケーション内で認証に必要な操作を行います。
-   セッションが期限切れになるまでアプリケーションをアイドル状態のままにします(テスト目的では、合理的なタイムアウトを設定し、後の最終バージョンで修正します)

傍受プロキシを使用して手順2で実行した操作の一つを再送信します。例えば、Burp Repeater を使用します。この目的はセッションが期限切れになったときに無効にされたセッション ID でサーバーにリクエストを送信することです。
セッションタイムアウトがサーバー側で正しく構成されている場合には、エラーメッセージまたはログインページへのリダイレクトがクライアントに戻されます。そうではなく、手順2で同じレスポンスがあった場合、このセッションはまだ有効であり、セッションタイムアウトが正しく構成されていないことを意味します。
詳細については OWASP Web Testing Guide (OTG-SESS-007) <sup>[1]</sup> にもあります。

#### 改善方法

ほとんどのフレームワークにはセッションタイムアウトを構成するパラメータがあります。このパラメータはフレームワークのドキュメントで指定されているベストプラクティスに応じて設定する必要があります。ストプラクティスのタイムアウトは10分から2時間までさまざまで、アプリケーションの機密性やそのユースケースによって変化します。

#### 参考情報

##### OWASP Mobile Top 10 2016
* M4 - 安全でない認証 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS
* 4.7: "非アクティブな状態で所定の期間経過後、リモートエンドポイントでセッションを終了している。"

##### CWE
- CWE-613 - Insufficient Session Expiration

##### その他
* [1] OWASP Web Application Test Guide (OTG-SESS-007) -  https://www.owasp.org/index.php/Test_Session_Timeout_(OTG-SESS-007)
* [2] OWASP Session management cheatsheet https://www.owasp.org/index.php/Session_Management_Cheat_Sheet


### 二要素認証のテスト

#### 概要

https://authy.com/blog/security-of-sms-for-2fa-what-are-your-options/
-- TODO [Provide a general description of the issue "Testing 2-Factor Authentication".] --

#### 静的解析

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm remark on "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

-- TODO [Develop content on Testing 2-Factor Authentication with source code] --


#### 動的解析

-- TODO [Describe how to test for this issue "Testing 2-Factor Authentication" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing 2-Factor Authentication".] --

#### 参考情報

##### OWASP Mobile Top 10 2016
* M4 - 安全でない認証 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS
* 4.8: "リモートエンドポイントに二要素認証が存在し、リモートエンドポイントで二要素認証要件が一貫して適用されている。"

##### CWE

-- TODO [Add relevant CWE for "Testing 2-Factor Authentication"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### その他

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### ツール

-- TODO [Add relevant tools for "Testing 2-Factor Authentication"] --
* Enjarify - https://github.com/google/enjarify




### ステップアップ認証のテスト

#### 概要

-- TODO [Provide a general description of the issue "Testing Step-up Authentication".] --

#### 静的解析

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm remark on "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>." ] --

-- TODO [Develop content on Testing Step-up Authentication with source code] --

#### 動的解析

-- TODO [Describe how to test for this issue "Testing Step-up Authentication" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing Step-up Authentication".] --

#### 参考情報

##### OWASP Mobile Top 10 2016
* M4 - 安全でない認証 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS
* 4.9: "機密データやトランザクションを処理するアクションを有効にするには、ステップアップ認証が必要とされている。"

##### CWE

-- TODO [Add relevant CWE for "Testing Step-up Authentication"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### その他

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### ツール

-- TODO [Add relevant tools for "Testing Step-up Authentication"] --
* Enjarify - https://github.com/google/enjarify


### ユーザーデバイス管理のテスト

#### 概要

-- TODO [Provide a general description of the issue "Testing User Device Management".] --

#### 静的解析

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm remark on "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

--TODO [Develop content on Testing User Device Management with source code] --


#### 動的解析

-- TODO [Describe how to test for this issue "Testing User Device Management" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### 改善方法

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing User Device Management".] --

#### 参考情報

##### OWASP Mobile Top 10 2016
* M4 - 安全でない認証 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS
* 4.10: "アプリはユーザーのアカウントでのすべてのログインアクティビティをユーザーに通知している。ユーザーはアカウントへのアクセスに使用されるデバイスの一覧を表示し、特定のデバイスをブロックすることができる。"

##### CWE

-- TODO [Add relevant CWE for "Testing User Device Management"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### その他

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### ツール

-- TODO [Add relevant tools for "Testing User Device Management"] --
* Enjarify - https://github.com/google/enjarify
