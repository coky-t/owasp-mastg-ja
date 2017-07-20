## リモート認証と認可

以下の章ではテクニカルテストケースでの MASVS の認証とセッション管理要件について説明します。この章に記載されるテストケースはサーバー側に焦点を当てているため、iOS や Android の特定の実装に依存しません。

以下のすべてのテストケースでは、まずどのような種類の認証メカニズムが使用されているかを調べる必要があります。サーバー側認証を実装するには、以下のいずれかの方法が利用できます。
* セッション ID を使用したクッキーベースの認証
* トークンベースの認証

クッキーベースの認証は Web アプリケーションで使用される従来の認証メカニズムで、ステートフルです。モバイルアプリのさまざまな要件に対応するため、ステートレス認証やトークンベースの認証への移行が見られます。これの顕著な例は OAuth2 認証および認可のフレームワークである JSON Web Token または JWT <sup>[1]</sup> です。

#### OAuth2

OAuth2 は認可フレームワークであり、アプリケーションを認可するために使用され、限定された時間に HTTP サービス上でユーザーアカウントを使用します。同時に、クライアントアプリケーションがユーザー資格情報を知ることを防ぎます。

OAuth2 は 4 つの役割を定義します。

* リソース所有者：アカウントを所有しているユーザー。
* クライアント：アクセストークンを使用してユーザーのアカウントにアクセスするアプリケーション。
* リソースサーバー：ユーザーアカウントをホストする。
* 認可サーバー：ユーザーの身元を検証し、アプリケーションのアクセストークンを発行する。

注意：API はリソースサーバーと認可サーバーの役割の両方を満たします。したがって、両方を API と呼ぶことにします。

<img src="Images/Chapters/0x07a/abstract-oauth2-flow.png" width="350px"/>

図 <sup>[1]</sup> <sup>[2]</sup> の手順の詳細な説明は以下のとおりです。

1. アプリケーションはユーザーにサービスリソースへアクセスするための認可を要求する。
2. ユーザーが要求を認可した場合、アプリケーションは認可許可を受け取る。認可許可にはさまざまな形式 (明示的、暗黙的など) がある。
3. アプリケーションは、それ自身のIDの認証と認可許可を提示することにより、認可サーバー (API) にアクセストークンを要求する。
4. アプリケーション ID が認証され、認可許可が有効である場合、認可サーバー (API) はアプリケーションにアクセストークンを発行する。アクセストークンにはコンパニオンリフレッシュトークンが含まれる可能性がある。認可は完了した。
5. アプリケーションはリソースサーバー (API) にリソースを要求し、認証用のアクセストークンを提示する。アクセストークンは異なる方法で (ベアラトークンとしてなど) 使用される可能性がある。
6. アクセストークンが有効である場合、リソースサーバー (API) はアプリケーションにリソースを提供する。

これらはネイティブアプリでの OAuth2 の一般的なベストプラクティスの一部です。

ユーザーエージェント:
- 埋め込まれたユーザーエージェント (WebView や内部クライアントユーザーインタフェースなど) の代わりに外部ユーザーエージェント (ブラウザ) を使用して、エンドユーザー資格情報のフィッシングを防止する (例えば、アプリが「Facebook でログイン」を提供して、あなたの Facebook パスワードを取得することは望まないだろう) 。しかし、ブラウザを使用することにより、アプリはサーバーの信頼のために OS キーチェーンに依存する。この方法では証明書ピンニングを実装することはできない。このためのソリューションは埋め込まれたユーザーエージェントを関連するドメインのみに制限することである。
- ユーザーは視覚的に信頼するメカニズム (トランスポート層セキュリティ (TLS) 確認、ウェブサイトメカニズムなど) を検証する方法を有するべきである。
- クライアントは接続確立時にサーバーにより提示される公開鍵にサーバーの完全修飾ドメイン名を妥当性検査し、中間者攻撃を防ぐべきである。

グラントの種類:
- ネイティブアプリで implicit グラントの代わりに code グラントを使用する。
- code グラントを使用する場合、code グラントを保護するために PKCE (Proof Key for Code Exchange) を実装する。サーバーもそれを実装していることを確認する。
- 認可 "code" は短命であり、それを受信した直後にのみ使用されるべきである。transient メモリにのみ存在し、保存またはログに記録されていないことを確認する。

クライアントの機密情報:
- クライアントの身元を証明するものとして共有の機密情報を使用すべきではない。これはクライアントの成りすましにつながる可能性がある ("client_id" はすでにこの目的を果たしている) 。何らかの理由でクライアントの機密情報を使用する場合、それらがセキュアなローカルストレージに格納されていることを確認する。

エンドユーザーの資格情報:
- エンドユーザーの資格情報の送信は TLS などのトランスポート層メカニズムを使用して保護する必要がある。

トークン:
- アクセストークンを transient メモリに保持する。
- アクセストークンは TLS を介してセキュアに送信する必要がある。
- エンドツーエンドの機密性が保証されない場合、またはトークンが機密情報へのアクセスを提供する場合、またはトークンがハイリスクのアクションの実行を許可する場合、アクセストークンのスコープと有効期間を短縮すべきである。
- アプリがアクセストークンをベアラトークンとして使用し、クライアントを識別するために追加のメカニズムを使用しない場合、攻撃者はトークンを盗んだ後にトークンとそのスコープに関連するすべてのリソースにアクセスできることに注意する。
- 長期的な資格情報である場合、セキュアなローカルストレージにリフレッシュトークンを格納する。

ベストプラクティスと詳細情報についてはソースドキュメント <sup>[2]</sup> <sup>[3]</sup> <sup>[4]</sup> を参照ください。

##### 参考情報
- [1] An Introduction into OAuth2 - https://www.digitalocean.com/community/tutorials/an-introduction-to-oauth-2
- [2] RFC6749: The OAuth 2.0 Authorization Framework (October 2012) - https://tools.ietf.org/html/rfc6749
- [3] draft_ietf-oauth-native-apps-12: OAuth 2.0 for Native Apps (June 2017) - https://tools.ietf.org/html/draft-ietf-oauth-native-apps-12
- [4] RFC6819: OAuth 2.0 Threat Model and Security Considerations (January 2013) - https://tools.ietf.org/html/rfc6819



### ユーザーが正しく認証されていることの検証

#### 概要

アプリケーションは、一方では公的で非特権的な情報や機能、他方で機密性が高く特権的な情報や機能といったさまざまなエリアを有することがよくあります。ユーザーは前者に制限なしで合法的にアクセスできます。しかし、機密性が高く特権的な情報や機能は正当なユーザーだけに保護されアクセスできるようにするために、適切な認証が行われる必要があります。

認証は常にサーバー側コードで処理する必要があり、クライアント側のコントロールに頼るべきではありません。ユーザーのワークフローを改善するために、クライアント側のコントロールを使用して特定のアクションのみを許可することはできますが、ユーザーがアクセスできるものを定義するサーバー側の対応が常に必要です。

JWT によるトークンベースの認証が使用される場合は、「JSON Web Token (JWT) のテスト」も参照ください。

#### 静的解析

サーバー側ソースコードが入手可能である場合は、まずサーバー側で使用および実施されている認証メカニズム(トークンまたはクッキーベース)を特定します。それから機密性が高く特権的な情報や機能を持つすべてのエンドポイントを突き止めます。それらは保護する必要があるものです。アイテムにアクセスする前に、アプリケーションはユーザーが実際に誰でありエンドポイントにアクセスすることを許可されていることを確認する必要があります。ユーザーを認証したり既存のセッションを取得およびチェックするために使用されるサーバーソースコードのキーワードを探します。

認証メカニズムはゼロから実装するのではなく、この機能を提供するフレームワーク上に構築すべきです。サーバー側で使用されるフレームワークを特定し、利用可能な認証 API や関数を使用してベストプラクティスに応じて使用されるかどうか検証すべきです。サーバー側で広く使用されるフレームワークは以下のとおりです。

- Spring (Java) - https://projects.spring.io/spring-security/
- Struts (Java) - https://struts.apache.org/docs/security.html
- Laravel (PHP) - https://laravel.com/docs/5.4/authentication
- Ruby on Rails -  http://guides.rubyonrails.org/security.html

#### 動的解析

認証を検証するには、まずユーザーがアプリ内でアクセスできるすべての特権エンドポイントを調べるべきです。エンドポイントに送信されるすべてのリクエストに対して、傍受プロキシを使用して認証されている間のネットワークトラフィックを取得します。次に、認証情報を削除してリクエストの再生を試みます。エンドポイントが依然としてリクエストされたデータを送り返している場合、認証されたユーザーにのみ利用可能にすべきであり、認証チェックがエンドポイントで正しく実装されていません。

さらなる攻撃方法については Web ベースアプリケーションに関する OWASP テストガイド V4 (OTG-AUTHN-004) <sup>[3]</sup> にあります。また、OWASP テストガイド <sup>[2]</sup> には多くの認証についてのテストケースがあります。

#### 改善方法

保護が必要なセクションごとに、ユーザーのセッション ID やトークンをチェックするメカニズムを実装します。
- セッション ID やトークンがない場合、ユーザーは以前に認証されていない可能性があります。
- セッション ID やトークンが存在する場合、それが有効であり、ユーザーがそのセクションにアクセスするのに十分な特権を付与されることを確認します。

これらの2つの条件のいずれかが問題を引き起こす場合、リクエストを拒否して、ユーザーがアクティビティを開始できないようにします。

#### 参考情報

##### OWASP Mobile Top 10 2016

* M4 - 安全でない認証 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS

- 4.1: "アプリがリモートサービスへのアクセスを提供する場合、ユーザー名/パスワード認証など許容される形態の認証がリモートエンドポイントで実行されている。"

##### CWE

- CWE-287: Improper Authentication - https://cwe.mitre.org/data/definitions/287.html

##### その他

* [1] OWASP JWT Cheat Sheet for Java: https://www.owasp.org/index.php/JSON_Web_Token_(JWT)_Cheat_Sheet_for_Java
* [2] OWASP Testing Guide V4 (Testing for Session Management) - https://www.owasp.org/index.php/Testing_for_Session_Management
* [3] OWASP Testing Guide V4 (OTG-AUTHN-004) - https://www.owasp.org/index.php/Testing_for_Bypassing_Authentication_Schema_(OTG-AUTHN-004)


### セッション管理のテスト

#### 概要

権限がない場合、すべての重要なアクションはユーザーが適切に認証された後に実行する必要があります。アプリケーションはセッション内のユーザーを覚えています。不適切に管理される場合、セッションはさまざまな攻撃が行われ、正規のユーザーのセッションが悪用され、攻撃者がユーザーに成りすます可能性があります。その結果、データが失われたり、機密性が損なわれたり、不正行為が行われたりする可能性があります。

セッションには開始と終了が必要です。攻撃者がセッション ID を偽造することは不可能である必要があります。代わりに、セッションがサーバー側のシステムによってのみ開始できるようにする必要があります。また、セッションの持続時間は可能な限り短くすべきであり、セッションは一定時間が経過するか、ユーザーが明示的にログアウトした後に適切に終了する必要があります。セッション ID を再利用することは不可能である必要があります。

したがって、このテストのスコープは、セッションがセキュアに管理され、攻撃者により侵害されないことを検証することです。

#### 静的解析

サーバーのソースコードが利用可能である場合、テスト担当者はセッションが開始、保存、交換、検証、終了される場所を探します。これは特権の必要な情報やアクションへのアクセスが行われるたびに実行する必要があります。これらの事項について、自動ツールや手動検索を使用して、ターゲットプログラミング言語の関連するキーワードを探します。サーバー側のフレームワークの例は以下のとおりです。

- Spring (Java) - http://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/#ns-session-mgmt
- PHP - http://php.net/manual/en/book.session.php
- Ruby on Rails -  http://guides.rubyonrails.org/security.html

#### 動的解析

ベストプラクティスは手動または自動ツールでアプリケーションをクロールすることです。目的は特権の必要な情報やアクションにつながるアプリケーションのすべての部分が保護され、有効なセッション ID が要求されているかどうかをチェックすることです。

次に、傍受プロキシ内でクロールされたリクエストを使用して、セッション ID の操作を試みます。
- それらを不正なものに改変する (例えば、有効なセッション ID に 1 を加える、その一部を削除するなど) 。
- リクエスト内の有効なものを削除し、アプリケーションの情報や機能が依然としてアクセスできるかどうかをテストする。
- ログアウトおよび再ログインし、セッション ID が変更されているかどうかを確認する。
- 特権レベルを変更 (ステップアップ認証) する場合。以前のものを使用して (つまり低い認可レベルで) 、アプリケーションの特権部分にアクセスを試みる。
- ログアウト後にセッション ID の再使用を試みる。

また、OWASP Testing Guide <sup>[1]</sup> にあるセッション管理テストケースも参照します。

#### 改善方法

前述の攻撃に対する適切な保護を提供するために、セッション ID は以下を満たす必要があります。
- 常にサーバー側で作成される必要がある、
- 予測できてはいけない (適切な長さとエントロピを使用する) 、
- 常にセキュアな接続 (HTTPS など) の上で交換する、
- モバイルアプリ内にセキュアに格納する、
- ユーザーがアプリケーションの特権が必要な部分にアクセスを試みる場合には検証する (セッション ID は有効で、適切な認可レベルに対応している必要がある) 、
- より高い権限を要求する操作を実行するため、ユーザーが再度ログインすることを求められた場合には更新する、
- ユーザーがログアウトする場合、または指定されたタイムアウト後にはサーバー側で終了し、モバイルアプリ内で削除する。

使用するフレームワーク内に組み込まれているセッション ID ジェネレータを使用することを強く推奨します。それらはカスタムなものを構築するよりもセキュアです。ほとんどのフレームワークや言語にはそのようなジェネレータが存在します。

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

* OWASP ZAP (Zed Attack Proxy)
* Burp Suite



### JSON Web Token (JWT) のテスト

#### 概要

JSON Web Token (JWT) は二者間の JSON オブジェクト内の情報の完全性を保証します。RFC 7519 <sup>[1]</sup> で定義されています。トークン内のデータに対して暗号署名が作成されます。これにより、サーバーはトークンの作成および変更だけが可能になり、ステートレス認証が可能になります。サーバーはセッションやその他の認証情報を覚える必要はありません。すべては JWT 内に含まれます。

エンコードされた JSON Web Token の例を以下に示します <sup>[5]</sup> 。

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ
```

JWT は Base-64 でエンコードされ、三つの部分に分けられます。

* **ヘッダ** アルゴリズムとトークンタイプ (eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9):
```JSON
{"alg":"HS256","typ":"JWT"}
```
* **クレーム** データ  (eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9):
```JSON
{"sub":"1234567890","name":"John Doe","admin":true}
```
* **JSON Web Signature (JWS)** (TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ):
```JSON
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  secret
)
```

モバイルアプリでは、JWT を使用してメッセージ送信者と受信者の両方を認証することがますます増えています。JWT 実装は PHP <sup>[2]</sup> や Java Spring <sup>[3]</sup> などすべての主要なプログラミング言語で利用できます。

#### 静的解析

サーバー側とクライアント側で使用される JWT ライブラリを特定します。使用中の JWT ライブラリに利用可能な既知の脆弱性が存在するかどうか確認します。

以下のベストプラクティスを JWT ライブラリにチェックすべきです <sup>[7]</sup> 。
* トークンを含むすべての着信リクエストについて、サーバー側の署名または HMAC を常に確認する。
* HMAC の秘密署名鍵または共通鍵がどこに配置および格納されるかを確認する。鍵は常にサーバー側に存在すべきであり、クライアントと共有してはいけない。それは発行者と検証者のためにのみ利用可能であるべき。
* JWT に埋め込まれたデータを暗号化するために、暗号化が使用されているかどうかを確認する。
* JWT の一意の識別子を提供する `jti` (JWT ID) クレームを使用して、リプレイ攻撃が対処されているかどうかを確認する。


#### 動的解析

動的解析を実行する中で JWT の既存の脆弱性をチェックすべきです。
* ハッシュアルゴリズム `none` <sup>[6]</sup>:
  * トークンヘッダの `alg` 属性を修正する。`HS256` を削除し、それに `none` を設定する。空の署名 (signature = "" など) を使用する。このトークンを使用し、リクエストでリプレイする。一部のライブラリは none アルゴリズムで署名されたトークンを、検証済みの有効なトークンとして扱う。これにより攻撃者は独自の「署名付き」トークンを作成できる。
* 非対称アルゴリズムの使用 <sup>[6]</sup>:
  * JWT は RSA や ECDSA などのいくつかの非対称アルゴリズムを提供している。この場合、秘密鍵はトークンに署名するために使用され、検証は公開鍵を介して行われる。サーバーが RSA などの非対称アルゴリズムで署名されたトークンを期待しているが、実際には HMAC で署名されたトークンを受信する場合、公開鍵は実際には HMAC 共通鍵であると考えられる。公開鍵が HMAC 共通鍵として誤用され、トークンに署名している可能性があり。
* クライアント側のトークンストレージ:
  * JWT を使用するモバイルアプリを使用する場合、トークンがローカルのデバイスのどこに格納されているかを確認すべきである <sup>[5]</sup> 。
* 署名鍵のクラック:
  * トークンの署名を作成するにはサーバー側の秘密鍵を使用する。JWT を取得すると、オフラインで共通鍵をブルートフォースできるいくつかのツールが利用できる <sup>[8]</sup> 。詳細についてはツールのセクションを参照する。
* 情報開示:
  * Base-64 でエンコードされた JWT をデコードし、その中でどのような種類のデータが送信されているか、それは暗号化されているか否かを確認する。

OWASP JWT Cheat Sheet<sup>[4]</sup> のテストケースも参照ください。また、「ログアウト機能のテスト」の説明にしたがってログアウトの実装をチェックします。

#### 改善方法

JWT を実装する場合には、以下のベストプラクティスを考慮すべきです。

* 使用している JWT ライブラリの利用可能な最終バージョンで実装し、既知の脆弱性を避ける。
* 異なる署名タイプのトークンはリジェクトされることが保証されていることを確認する。
* iOS の KeyChain や Android の KeyStore などのセキュアなメカニズムを使用して、モバイルフォンに JWT を格納する。
* HMAC の秘密署名鍵または共通鍵はサーバー側でのみ利用可能であるべき。
* リプレイ攻撃がアプリのリスクである場合、`jti` (JWT ID) クレームを実装すべきである。* 理想的には JWT の内容は暗号化し、その中に含まれる情報の機密性を保証すべきである。保護すべきロール、ユーザー名、その他の利用可能な機密情報が記載されている可能性がある。Java の実装例は OWASP JWT Cheat Sheet <sup>[4]</sup> にある。
* 別のデバイスにトークンをコピーする場合、攻撃者が認証を継続できないようにすべきである。これを強制するには、デバイスバインディングのテストケースを確認する。

#### 参考情報

##### OWASP Mobile Top 10 2016

* M4 - 安全でない認証 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS

* 4.3: "The remote endpoint uses server side signed tokens, if stateless authentication is used, to authenticate client requests without sending the user's credentials."

##### CWE

* CWE-287: Improper Authentication - https://cwe.mitre.org/data/definitions/287.html

##### その他

* [1] RFC 7519 JSON Web Token (JWT) - https://tools.ietf.org/html/rfc7519
* [2] PHP JWT - https://github.com/firebase/php-jwt
* [3] Java Spring with JWT - http://projects.spring.io/spring-security-oauth/docs/oauth2.html
* [4] OWASP JWT Cheat Sheet - https://www.owasp.org/index.php/JSON_Web_Token_(JWT)_Cheat_Sheet_for_Java
* [5] Sample of JWT Token - https://jwt.io/#debugger
* [6] Critical Vulnerabilities in JSON Web Token - https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
* [7] JWT the right way - https://stormpath.com/blog/jwt-the-right-way
* [8] Attacking JWT Authentication - https://www.sjoerdlangkemper.nl/2016/09/28/attacking-jwt-authentication/

##### ツール
* jwtbrute - https://github.com/jmaxxz/jwtbrute
* crackjwt - https://github.com/Sjord/jwtcrack/blob/master/crackjwt.py
* John the ripper - https://github.com/magnumripper/JohnTheRipper



### Testing the Logout Functionality

#### Overview

Reducing the lifetime of session identifiers and tokens to a minimum decreases the likelihood of a successful account hijacking attack. The scope for this test case is to validate that the application has a logout functionality and it effectively terminates the session on client and server side or invalidates a stateless token.

One of the most common errors done when implementing a logout functionality is simply not destroying the session object or invalidating the token on server side. This leads to a state where the session or token is still alive even though the user logs out of the application. If an attacker get’s in possession of valid authentication information he can continue using it and hijack a user account.

##### Static Analysis 

If server side code is available, it should be reviewed that the session is being terminated or token invalidated as part of the logout functionality. The check needed here will be different depending on the technology used. Here are different examples on how a session can be terminated in order to implement a proper logout on server side:
- Spring (Java) -  http://docs.spring.io/spring-security/site/docs/current/apidocs/org/springframework/security/web/authentication/logout/SecurityContextLogoutHandler.html
- Ruby on Rails -  http://guides.rubyonrails.org/security.html
- PHP - http://php.net/manual/en/function.session-destroy.php

For stateless authentication the access token and refresh token (if used) should be deleted from the mobile device and the refresh token should be invalidated on server side<sup>[1]</sup>.

#### Dynamic Analysis

For a dynamic analysis of the application an interception proxy should be used. The following steps can be applied to check if the logout is implemented properly.  
1.  Log into the application.
2.  Do a couple of operations that require authentication inside the application.
3.  Perform a logout operation.
4.  Resend one of the operations detailed in step 2 using an interception proxy. For example, with Burp Repeater. The purpose of this is to send to the server a request with the session ID or token that has been invalidated in step 3.
 
If the logout is correctly implemented on the server side, either an error message or redirect to the login page will be sent back to the client. On the other hand, if you have the same response you had in step 2, then the token or session ID is still valid and has not been correctly terminated on the server side.
A detailed explanation with more test cases, can also be found in the OWASP Web Testing Guide (OTG-SESS-006)<sup>[2]</sup>.

#### Remediation 

The logout function on the server side must invalidate the session identifier or token immediately after logging out to prevent it to be reused by an attacker that could have intercepted it<sup>[3]</sup>.

Many mobile apps do not automatically logout a user, because of customer convenience by implementing stateless authentication. There should still be a logout function available within the application and this should work accordingly to best practices by also destroying the access and refresh token on client and server side. Otherwise this could lead to another authentication bypass in case the refresh token is not invalidated.

#### References

##### OWASP Mobile Top 10 2016
* M4 - Insecure Authentication - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS

* 4.4: "The remote endpoint terminates the existing session or server side signed tokens when the user logs out."

##### CWE

* CWE-613 - Insufficient Session Expiration

##### Info

* [1] JWT token blacklisting - https://auth0.com/blog/blacklist-json-web-token-api-keys/
* [2] OTG-SESS-006 - https://www.owasp.org/index.php/Testing_for_logout_functionality
* [3] Session Management Cheat Sheet - https://www.owasp.org/index.php/Session_Management_Cheat_Sheet



### Testing the Password Policy

#### Overview

Password strength is a key concern when using passwords for authentication. Password policy defines requirements that end users should adhere to. Password length, password complexity and password topologies should properly be included in the password policy. A "strong" password policy makes it difficult or even infeasible for one to guess the password through either manual or automated means.


#### Static Analysis

Regular Expressions are often used to validate passwords. The password verification check against a defined password policy need to be reviewed if it rejects passwords that violate the password policy.

Passwords can be set when registering accounts, changing the password or when resetting the password in a forgot password process. All of the available functions in the application that are able to change or set a password need to be identified in the source code. They should all be using the same password verification check, that is aligned with the password policy.

Here are different examples on how a validation can be implemented server-side:

* Spring (Java) -  https://docs.spring.io/spring/docs/current/javadoc-api/org/springframework/validation/Validator.html
* Ruby on Rails -  http://guides.rubyonrails.org/active_record_validations.html
* PHP - http://php.net/manual/en/filter.filters.validate.php

If a framework is used that offers the possibility to create and enforce a password policy for all users of the application, the configuration should be checked.

#### Dynamic Analysis

All available functions that allow a user to set a password need to be verified, if passwords can be used that violate the password policy specifications. This can be:

- Self-registration function for new users that allows to specify a password,
- Forgot Password function that allows a user to set a new password or
- Change Password function that allows a logged in user to set a new password.

An interception proxy should be used, to bypass client passwords checks within the app in order to be able verify the password policy implemented on server side. More information about testing methods can be found in the OWASP Testing Guide (OTG-AUTHN-007)<sup>[1]</sup>


#### Remediation

A good password policy should define the following requirements<sup>[2]</sup> in order to avoid password brute-forcing:

**Password Length**
* Minimum length of the passwords should be enforced, at least 10 characters.
* Maximum password length should not be set too low, as it will prevent users from creating passphrases. Typical maximum length is 128 characters.

**Password Complexity**
* Password must meet at least 3 out of the following 4 complexity rules
1. at least 1 uppercase character (A-Z)
2. at least 1 lowercase character (a-z)
3. at least 1 digit (0-9)
4. at least 1 special character (punctuation)

For further details check the OWASP Authentication Cheat Sheet<sup>[2]</sup>. A common library that can be used for estimating password strength is zxcvbn<sup>[3]</sup>, which is availalbe for many programming languages. 


#### References

##### OWASP Mobile Top 10 2016
* M4 - Insecure Authentication - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS
* 4.5: "A password policy exists and is enforced at the remote endpoint."

##### CWE
* CWE-521 - Weak Password Requirements

##### Info
* [1] OWASP Testing Guide (OTG-AUTHN-007) - https://www.owasp.org/index.php/Testing_for_Weak_password_policy_(OTG-AUTHN-007)
* [2] OWASP Authentication Cheat Sheet - https://www.owasp.org/index.php/Authentication_Cheat_Sheet#Implement_Proper_Password_Strength_Controls
* [3] zxcvbn - https://github.com/dropbox/zxcvbn


### Testing Excessive Login Attempts

#### Overview

We all have heard about brute force attacks. This is one of the simplest attack types, as already many tools are available that work out of the box. It also doesn’t require a deep technical understanding of the target, as only a list of username and password combinations is sufficient to execute the attack. Once a valid combination of credentials is identified access to the application is possible and the account can be taken over.
 
To be protected against these kind of attacks, applications need to implement a control to block the access after a defined number of incorrect login attempts.
 
Depending on the application that you want to protect, the number of incorrect attempts allowed may vary. For example, in a banking application it should be around three to five attempts, but, in a app that doesn't handle sensitive information it could be a higher number. Once this threshold is reached it also needs to be decided if the account gets locked permanently or temporarily. Locking the account temporarily is also called login throttling.
 
The test consists by entering the password incorrectly for the defined number of attempts to trigger the account lockout. At that point, the anti-brute force control should be activated and your logon should be rejected when the correct credentials are entered.

#### Static Analysis

It need to be checked that a validation method exists during logon that checks if the number of attempts for a username equals to the maximum number of attempts set. In that case, no logon should be granted once this threshold is meet. After a correct attempt, there should also be a mechanism in place to set the error counter to zero.


#### Dynamic Analysis

For a dynamic analysis of the application an interception proxy should be used. The following steps can be applied to check if the lockout mechanism is implemented properly.  
1.  Log in incorrectly for a number of times to trigger the lockout control (generally 3 to 15 incorrect attempts). This can be automated by using Burp Intruder<sup>[5]</sup>.
2.  Once you have locked out the account, enter the correct logon details to verify if login is not possible anymore.
If this is correctly implemented logon should be denied when the right password is entered, as the account has already been blocked.

#### Remediation

Lockout controls have to be implemented on server side to prevent brute force attacks. Further mitigation techniques are described by OWASP in Blocking Brute Force Attacks<sup>[3]</sup>.
It is interesting to clarify that incorrect login attempts should be cumulative and not linked to a session. If you implement a control to block the credential in your 3rd attempt in the same session, it can be easily bypassed by entering the details wrong two times and get a new session. This will then give another two free attempts.

Alternatives to locking accounts are enforcing 2-Factor-Authentication (2FA) for all accounts or the usage of CAPTCHAS. See also Credential Cracking OAT-007 in the OWASP Automated Thread Handbook<sup>[4]</sup>.

#### References

##### OWASP Mobile Top 10 2016
* M4 - Insecure Authentication - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS
* 4.6: "The remote endpoint implements an exponential back-off, or temporarily locks the user account, when incorrect authentication credentials are submitted an excessive number of times ."

##### CWE

- CWE-307 - Improper Restriction of Excessive Authentication Attempts

##### Info
* [1] OTG-AUTHN-003 - https://www.owasp.org/index.php/Testing_for_Weak_lock_out_mechanism
* [2] Brute Force Attacks - https://www.owasp.org/index.php/Brute_force_attack
* [3] Blocking Brute Force Attacks - https://www.owasp.org/index.php/Blocking_Brute_Force_Attacks
* [4] OWASP Automated Threats to Web Applications - https://www.owasp.org/index.php/OWASP_Automated_Threats_to_Web_Applications
* [5] Burp Intruder - https://portswigger.net/burp/help/intruder.html

##### Tools
* Burp Suite Professional - https://portswigger.net/burp/
* OWASP ZAP - https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project



### Testing the Session Timeout

#### Overview

Compared to web applications most mobile applications don’t have a visible timeout mechanism that terminates the session ID or token after some period of inactivity and force the user to login again. For most mobile applications users need to enter the credentials once and use a stateless authentication mechanism. Mobile apps that handle sensitive data like patient data or critical functions like financial transactions should implement a timeout as a security-in-depth measure that forces users to re-login after a defined period of time.
 
We will explain here how to check that this control is implemented correctly, both in the client and server side.

#### Static Analysis

If server side code is available, it should be reviewed that the session timeout or token invalidation functionality is correctly configured and a timeout is triggered after a defined period of time.  
The check needed here will be different depending on the technology used. Here are different examples on how a session timeout can be configured:
* Spring (Java) - http://docs.spring.io/spring-session/docs/current/reference/html5/
* Ruby on Rails - http://guides.rubyonrails.org/security.html#session-expiry
* PHP - http://php.net/manual/en/session.configuration.php#ini.session.gc-maxlifetime
* ASP.Net - https://msdn.microsoft.com/en-GB/library/system.web.sessionstate.httpsessionstate.timeout(v=vs.110).aspx

In case of stateless authentication, once a token is signed, it is valid forever unless the signing key is changed or expiration explicitly set. One could use "exp" expiration claim<sup>[3]</sup> to define the expiration time on or after which the JWT must not be accepted for processing.
Speaking of tokens for stateless authentication, one should differentiate types of tokens, such as access tokens and refresh tokens<sup>[4]</sup>. Access tokens are used for accessing protected resources and should be short-lived. Refresh tokens are primarily used to obtain renewed access tokens. They are rather long-lived but should expire too, as otherwise their leakage would expose the system for unauthorized use. 

The exact values for token expiration depend on the application requirements and capacity. Sample code for JWT token refreshments is presented below:
```
 app.post('/refresh_token', function (req, res) {
  // verify the existing token
  var profile = jwt.verify(req.body.token, secret);

  // if more than 14 days old, force login
  if (profile.original_iat - new Date() > 14) { // iat == issued at
    return res.send(401); // re-logging
  }

  // check if the user still exists or if authorization hasn't been revoked
  if (!valid) return res.send(401); // re-logging

  // issue a new token
  var refreshed_token = jwt.sign(profile, secret, { expiresInMinutes: 60*5 });
  res.json({ token: refreshed_token });
});
```

#### Dynamic Analysis

Dynamic analysis is an efficient option, as it is easy to validate if the session timeout is working or not at runtime using an interception proxy. This is similar to test case "Testing the Logout Functionality", but we need to leave the application in idle for the period of time required to trigger the timeout function. Once this condition has been launched, we need to validate that the session is effectively terminated on client and server side.

The following steps can be applied to check if the session timeout is implemented properly.  
1. Log into the application.
2. Do a couple of operations that require authentication inside the application.
3. Leave the application in idle until the session expires (for testing purposes, a reasonable timeout can be configured, and amended later in the final version)
 
Resend one of the operations executed in step 2 using an interception proxy, for example with Burp Repeater. The purpose of this is to send to the server a request with the session ID that has been invalidated when the session has expired.
If session timeout has been correctly configured on the server side, either an error message or redirect to the login page will be sent back to the client. On the other hand, if you have the same response you had in step 2, then, this session is still valid, which means that the session timeout is not configured correctly.
More information can also be found in the OWASP Web Testing Guide (OTG-SESS-007)<sup>[1]</sup>.

#### Remediation

Most of the frameworks have a parameter to configure the session timeout. This parameter should be set accordingly to the best practices specified of the documentation of the framework. The best practice timeout setting may vary between 10 minutes to two hours, depending on the sensitivity of your application and the use case of it.

#### References

##### OWASP Mobile Top 10 2016
* M4 - Insecure Authentication - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS
* 4.8: "Sessions and server side signed tokens are terminated at the remote endpoint after a predefined period of inactivity."

##### CWE
- CWE-613 - Insufficient Session Expiration

##### Info
* [1] OWASP Web Application Test Guide (OTG-SESS-007) - https://www.owasp.org/index.php/Test_Session_Timeout_(OTG-SESS-007)
* [2] OWASP Session management cheatsheet - https://www.owasp.org/index.php/Session_Management_Cheat_Sheet
* [3] RFC 7519 - https://tools.ietf.org/html/rfc7519#section-4.1.4
* [4] Refresh tokens & access tokens - https://auth0.com/blog/refresh-tokens-what-are-they-and-when-to-use-them/


### Testing 2-Factor Authentication and Step-up Authentication

#### Overview

Two-factor authentication (2FA) is becoming a standard when logging into mobile apps. Typically the first factor might be credentials (username/password), followed by a second factor which could be an One Time Password (OTP) sent via SMS. The key aspect of 2FA is to use two different factors out of the following categories:
* Something you have: this can be a physical object like a hardware token, a digital object like X.509 certificates (in enterprise environments) or generation of software tokens on the mobile phone itself.
* Something you know: this can be a secret only known to the user like a password.
* Something you are: this can be biometric characteristics that identify the users like TouchID.

Applications that offer access to sensitive data or critical functions, might require users additionally to re-authenticate with a stronger authentication mechanism. For example, after logging in via biometric authentication (e.g. TouchID) into a banking app, a user might need to do a so called "Step-up Authentication" again through OTP in order to execute a bank transfer.

A key advantage of step-up authentication is improved usability for the user. A user is asked to authenticate with the additional factor only when necessary.


#### Static Analysis

When server-side source code is available, first identify how a second factor or step-up authentication is used and enforced. Afterwards locate all endpoints with sensitive and privileged information and functions: they are the ones that need to be protected. Prior to accessing any item, the application must make sure the user has already passed 2FA or the step-up authentication and that he is allowed to access the endpoint.

2FA or step-up authentication shouldn't be implemented from scratch, instead they should be build on top of available libraries that offer this functionality. The libraries used on the server side should be identified and the usage of the available APIs/functions should be verified if they are used accordingly to best practices.

For example server side libraries like GoogleAuth<sup>[2]</sup> can be used. Such libraries rely on a widely accepted mechanism of implementing an additional factor by using Time-Based One-Time Password Algorithms (TOTP). TOTP is a cryptographic algorithm that computes a OTP from a shared secret key between the client and server and the current time. The created OTPs are only valid for a short amount of time, usually 30 to 60 seconds.

Instead of using libraries in the server side code, also available cloud solutions can be used like for example:

- Google Authenticator<sup>[2]</sup>
- Microsoft Authenticator<sup>[3]</sup>
- Authy<sup>[4]</sup>

Regardless if the implementation is done within the server side or by using a cloud provider, the TOTP app need to be started and will display the OTP that need to be keyed in into the app that is waiting to authenticate the user.

For local biometric authentication as an additional factor, please verify the test case "Testing Biometric Authentication".

#### Dynamic Analysis

First, all privileged endpoints a user can only access with step-up authentication or 2FA within an app should be explored. For all of these requests sent to an endpoint, an interception proxy can be used to capture network traffic. Then, try to replay requests with a token or session information that hasn't been elevated yet via 2FA or step-up authentication. If the endpoint is still sending back the requested data, that should only be available after 2FA or step-up authentication, authentication checks are not implemented properly on the endpoint.

The recorded requests should also be replayed without providing any authentication information, in order to check for a complete bypass of authentication mechanisms.

#### Remediation

The implementation of a second or multiple factors should be strictly enforced on server-side for all critical operations. If cloud solutions are in place, they should be implemented accordingly to best practices.

Step-up authentication should be optional for the majority of user scenarios and only enforced for critical functions or when accessing sensitive data.

Regardless of 2FA or step-up authentication, additionally it should be supplemented with passive contextual authentication<sup>[1]</sup>, which can be:

* Geolocation
* IP address
* Time of day

Ideally the user's context is compared to previously recorded data to identify anomalies that might indicate account abuse or potential fraud. This is all happening transparent for the user, but can become a powerful control in order to stop attackers.

An additional control to ensure that an authorized user is using the app on an authorized device is to verify if device binding controls are in place. Please check also "Testing Device Binding" for iOS and Android.

#### References

##### OWASP Mobile Top 10 2016
* M4 - Insecure Authentication - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS

* 4.9: "A second factor of authentication exists at the remote endpoint and the 2FA requirement is consistently enforced."
* 4.10: "Step-up authentication is required to enable actions that deal with sensitive data or transactions."

##### CWE

- CWE-308 - Use of Single-factor Authentication

##### Info

* [1] Best Practices for Step-up Multi-factor Authentication  - http://www.mtechpro.com/2016/newsletter/may/Ping_Identity_best-practices-stepup-mfa-3001.pdf
* [2] Google Authenticator - https://support.google.com/accounts/answer/1066447?hl=en
* [3] Microsoft Authenticator - https://docs.microsoft.com/en-us/azure/multi-factor-authentication/end-user/microsoft-authenticator-app-how-to
* [4] Authy - https://authy.com/


### Testing User Device Management

#### Overview

-- TODO [Provide a general description of the issue "Testing User Device Management".] --

#### Static Analysis

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm remark on "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

--TODO [Develop content on Testing User Device Management with source code] --


#### Dynamic Analysis

-- TODO [Describe how to test for this issue "Testing User Device Management" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### Remediation

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing User Device Management".] --

#### References

##### OWASP Mobile Top 10 2016
* M4 - Insecure Authentication - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS
* 4.11: "The app informs the user of all login activities with his or her account. Users are able view a list of devices used to access the account, and to block specific devices."

##### CWE

-- TODO [Add relevant CWE for "Testing User Device Management"] --
- CWE-312: Cleartext Storage of Sensitive Information

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### Tools

-- TODO [Add relevant tools for "Testing User Device Management"] --
* Enjarify - https://github.com/google/enjarify
