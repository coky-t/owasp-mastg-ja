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



### ログアウト機能のテスト

#### 概要

セッション識別子およびトークンの生存期間を抑えることは、アカウントハイジャック攻撃が成功する可能性を低減させます。このテストケースのスコープは、アプリケーションがログアウト機能を持つこと、それがクライアントとサーバー側とで実際にセッションを終了すること、またはステートレストークンを無効にすること、を検証することです。

ログアウト機能を実装するときに最もよく起こるエラーのひとつは、単にセッションオブジェクトを破棄しないこと、またはサーバー側のトークンを無効にしないことです。これにより、ユーザーがアプリケーションからログアウトしても、セッションまたはトークンがまだ生きている状態になります。攻撃者が有効な認証情報を入手している場合、継続してそれを使用し、ユーザーアカウントを乗っ取ることが可能です。

##### 静的解析

サーバー側のコードが利用可能である場合には、ログアウト機能の一部としてセッションを終了しているか、もしくはトークンを無効にしているかをレビューすべきです。ここで必要なチェックは使用される技術によって異なります。サーバー側で適切なログアウトを実装するためにセッションを終了する方法の例を以下に示します。
- Spring (Java) -  http://docs.spring.io/spring-security/site/docs/current/apidocs/org/springframework/security/web/authentication/logout/SecurityContextLogoutHandler.html
- Ruby on Rails -  http://guides.rubyonrails.org/security.html
- PHP - http://php.net/manual/en/function.session-destroy.php

ステートレス認証では、アクセストークンとリフレッシュトークン (使用されている場合) をモバイルデバイスから削除し、リフレッシュトークンをサーバー側で無効にする必要があります <sup>[1]</sup> 。

#### 動的解析

アプリケーションの動的解析には傍受プロキシを使用する必要があります。以下の手順を実行して、ログアウトが適切に実装されているかどうかを確認します。
1.  アプリケーションにログインする。
2.  アプリケーション内で認証を必要とする操作をいくつか行う。
3.  ログアウト操作を実行する。
4.  傍受プロキシ (Burp Repeater など) を使用して、手順2で詳述されている操作のひとつを再送する。この目的は手順3で無効にされたセッション ID やトークンを使用してサーバーにリクエストを送信することである。

ログアウトがサーバー側で正しく実装されている場合は、エラーメッセージまたはログインページへのリダイレクトがクライアントに返送されます。一方で、手順2と同じレスポンスがある場合、トークンやセッション ID は有効であり、サーバー側で正しく終了していません。
OWASP Web Testing Guide (OTG-SESS-006) <sup>[2]</sup> には、更に多くのテストケースを含む詳細な説明があります。

#### 改善方法

サーバー側のログアウト機能はログアウトした直後にセッション識別子やトークンを無効にして、それを傍受した可能性のある攻撃者によって再利用されないようにする必要があります <sup>[3]</sup> 。

多くのモバイルアプリは自動的にユーザーをログアウトしません。ステートレス認証を実装することで顧客の利便性が高まるためです。アプリケーション内ではログアウト機能が利用可能であり、クライアント側とサーバー側とでアクセストークンとリフレッシュトークンを破棄することによりベストプラクティスとして機能します。もしくは、リフレッシュトークンが無効にされない場合、他の認証バイパスとなる可能性があります。

#### 参考情報

##### OWASP Mobile Top 10 2016
* M4 - 安全でない認証 - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS

* 4.4: "The remote endpoint terminates the existing session or server side signed tokens when the user logs out."

##### CWE

* CWE-613 - Insufficient Session Expiration

##### その他

* [1] JWT token blacklisting - https://auth0.com/blog/blacklist-json-web-token-api-keys/
* [2] OTG-SESS-006 - https://www.owasp.org/index.php/Testing_for_logout_functionality
* [3] Session Management Cheat Sheet - https://www.owasp.org/index.php/Session_Management_Cheat_Sheet



### パスワードポリシーのテスト

#### 概要

認証にパスワードを使用する場合、パスワードの強度は重要な事項です。パスワードポリシーはエンドユーザーが遵守すべき要件を定義します。パスワード長、パスワードの複雑さ、パスワードのトポロジーがパスワードポリシーに適切に含まれる必要があります。「強力な」パスワードポリシーは手動または自動のいずれかの方法でパスワードを推測することを困難または不可能にさえします。


#### 静的解析

パスワードの検証には正規表現がよく使用されます。定義されたパスワードポリシーに対するパスワード検証チェックは、パスワードポリシーに違反するパスワードを拒否するかどうかをレビューする必要があります。

アカウントの登録、パスワードの変更、パスワードを忘れた際のパスワードリセット時にパスワードを設定できます。パスワードを変更または設定できるアプリケーション内で利用可能なすべての機能をソースコード内で特定する必要があります。それらはパスワードポリシーに割り当てられた同じパスワード検証チェックをすべて使用する必要があります。

サーバー側で実装できる検証方法のさまざまな例を以下に示します。

* Spring (Java) -  https://docs.spring.io/spring/docs/current/javadoc-api/org/springframework/validation/Validator.html
* Ruby on Rails -  http://guides.rubyonrails.org/active_record_validations.html
* PHP - http://php.net/manual/en/filter.filters.validate.php

アプリケーションのすべてのユーザーに対してパスワードポリシーを作成および強制する可能性を提供するフレームワークを使用する場合、設定をチェックすべきです。

#### 動的解析

パスワードポリシー仕様に違反するパスワードが使用可能かどうか、ユーザーがパスワードを設定できるすべての利用可能な機能を検証する必要があります。これは以下のようになります。

- 新しいユーザーのためにパスワードを指定できる自己登録機能
- ユーザーが新しいパスワードを設定できるパスワード忘れ機能
- ログインユーザーが新しいパスワードを設定できるパスワード変更機能

傍受プロキシを使用し、アプリ内のクライアントパスワードチェックをバイパスし、サーバー側で実装されるパスワードポリシーを検証できるようにします。テスト手法についての詳細情報は OWASP Testing Guide (OTG-AUTHN-007) <sup>[1]</sup> を参照ください。


#### 改善方法

よいパスワードポリシーはパスワードブルートフォースを避けるために以下の要件 <sup>[2]</sup> を定義すべきです。

**パスワード長**
* パスワードの最小長は少なくとも10文字以上であること。
* パスワードの最大長は低すぎてはいけない。ユーザーがパスフレーズを作成することを妨げないこと。典型的な最大長は128文字である。

**パスワードの複雑さ**
* パスワードは以下の4つの複雑さのルールのうち少なくとも3つを満たす必要があります。
1. 少なくとも1つの大文字 (A-Z)
2. 少なくとも1つの小文字 (a-z)
3. 少なくとも1つの数字 (0-9)
4. 少なくとも1つの特殊文字 (記号)

詳細は OWASP Authentication Cheat Sheet <sup>[2]</sup> を参照ください。パスワード強度を推定するために使用できる共通ライブラリに zxcvbn <sup>[3]</sup> があり、多くのプログラミング言語で利用可能です。


#### 参考情報

##### OWASP Mobile Top 10 2016
* M4 - Insecure Authentication - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS
* 4.5: "パスワードポリシーが存在し、リモートエンドポイントで実施されている。"

##### CWE
* CWE-521 - Weak Password Requirements

##### その他
* [1] OWASP Testing Guide (OTG-AUTHN-007) - https://www.owasp.org/index.php/Testing_for_Weak_password_policy_(OTG-AUTHN-007)
* [2] OWASP Authentication Cheat Sheet - https://www.owasp.org/index.php/Authentication_Cheat_Sheet#Implement_Proper_Password_Strength_Controls
* [3] zxcvbn - https://github.com/dropbox/zxcvbn


### 過度のログイン試行のテスト

#### 概要

私たちはみなブルートフォース攻撃について聞いたことがあります。これは最も単純な攻撃タイプのひとつで、すでに多くのツールが用意されており、すぐに利用可能です。また、ターゲットの深い技術的な理解は必要なく、ユーザー名とパスワードの組み合わせのリストだけで攻撃を実行するのに十分です。資格情報の有効な組み合わせが識別されると、アプリケーションへのアクセスが可能になり、アカウントを奪うことができます。

この種の攻撃から保護するために、アプリケーションは定義された回数の不正なログイン試行後にアクセスをブロックするコントロールを実装する必要があります。

保護したいアプリケーションによって、許可される不正な試行回数が異なる場合があります。例えば、銀行業務アプリケーションでは三回から五回程度の試行とすべきですが、機密情報を処理しないアプリではそれ以上の回数になる可能性があります。この閾値に達したとき、アカウントを永続的にまたは一時的にロックするかどうかを決定する必要があります。一時的にアカウントをロックすることはログイン抑制とも呼ばれます。

テストは不正なパスワード入力を定義された回数分の試行し、アカウントロックアウトを引き起こすことにより行われます。この時点で、耐ブルートフォースコントロールが有効であり、正しい資格情報を入力した場合でもログオンが拒否されるべきです。

#### 静的解析

ログイン時にユーザー名に対する試行回数が最大試行回数に等しいかどうかを確認する検証メソッドが存在することを確認する必要があります。この場合、この閾値が満たされるとログオンは許可すべきではありません。正しい試行の後、エラーカウンタをゼロに設定するための仕組みも必要です。


#### 動的解析

アプリケーションの動的解析には、傍受プロキシを使用する必要があります。以下の手順を適用して、ロックアウトメカニズムが適切に実装されているかどうかを確認します。
1.  ロックアウトコントロールを引き起こす回数分の不正なログインを行う (一般的に 3 回から 15 回の不正な試行) 。これは Burp Intruder <sup>[5]</sup> を使用して自動化できる。
2.  アカウントをロックアウトしたら、正しいログオン情報を入力し、ログインが不可能であるかどうかを確認する。
これが正しく実装されている場合、正しいパスワードを入力しても、アカウントは既にブロックされているため、ログオンは拒否されます。

#### 改善方法

ロックアウトコントロールをサーバー側に実装して、ブルートフォース攻撃を防ぐ必要があります。さらなる軽減技法については OWASP が Blocking Brute Force Attacks <sup>[3]</sup> に記述しています。
不正なログイン試行が累積され、セッションにリンクされていないことを明確にすることは重要です。同じセッションでの3回目の試行で資格情報をブロックするようコントロールを実装した場合、誤った情報を二回入力してから新しいセッションを取得することで簡単にバイパスできます。これによりさらに二回の自由な試行が得られます。

アカウントをロックする代わりにすべてのアカウントに二要素認証 (2FA) または CAPTCHAS の使用を実施します。OWASP Automated Thread Handbook <sup>[4]</sup> の Credential Cracking OAT-007 も参照ください。

#### 参考情報

##### OWASP Mobile Top 10 2016
* M4 - Insecure Authentication - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS
* 4.6: "不正な認証資格情報が過度に送信される場合、リモートエンドポイントはExponential Backoffを実装しているか一時的にユーザーアカウントをロックしている。"

##### CWE

- CWE-307 - Improper Restriction of Excessive Authentication Attempts

##### その他
* [1] OTG-AUTHN-003 - https://www.owasp.org/index.php/Testing_for_Weak_lock_out_mechanism
* [2] Brute Force Attacks - https://www.owasp.org/index.php/Brute_force_attack
* [3] Blocking Brute Force Attacks - https://www.owasp.org/index.php/Blocking_Brute_Force_Attacks
* [4] OWASP Automated Threats to Web Applications - https://www.owasp.org/index.php/OWASP_Automated_Threats_to_Web_Applications
* [5] Burp Intruder - https://portswigger.net/burp/help/intruder.html

##### ツール
* Burp Suite Professional - https://portswigger.net/burp/
* OWASP ZAP - https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project



### セッションタイムアウトのテスト

#### 概要

ウェブアプリケーションと比較して、ほとんどのモバイルアプリケーションは、一定期間使用しない場合にセッション ID やトークンを終了し、ユーザーに再度ログインさせるような、明確なタイムアウトメカニズムがありません。ほとんどのモバイルアプリケーションではユーザーは資格情報を一度入力し、ステートレス認証メカニズムを使用します。患者データや金融取引のような重要な機能を扱うモバイルアプリは、定義された時間が経過した後にユーザーに再ログインさせるセキュリティ対策としてタイムアウトを実装すべきです。

ここではこのコントロールがクライアント側とサーバー側の両方で正しく実装されていることを確認する方法を説明します。

#### 静的解析

サーバー側コードが利用可能である場合は、セッションタイムアウトやトークン無効化機能が適切に設定されており、定義された時間が経過するとタイムアウトが発生することをレビューすべきです。
ここで必要なチェックは使用する技術により異なります。セッションタイムアウトを設定する方法の例を以下に示します。
* Spring (Java) - http://docs.spring.io/spring-session/docs/current/reference/html5/
* Ruby on Rails - http://guides.rubyonrails.org/security.html#session-expiry
* PHP - http://php.net/manual/en/session.configuration.php#ini.session.gc-maxlifetime
* ASP.Net - https://msdn.microsoft.com/en-GB/library/system.web.sessionstate.httpsessionstate.timeout(v=vs.110).aspx

ステートレス認証の場合、トークンを署名した後は、署名鍵を変更したり期限を明示的に設定したりしない限り、永久に有効です。"exp" 期限切れクレーム <sup>[3]</sup> を使用して、JWT が処理のために受け入れてはいけない期限切れ時刻を定義できます。
ステートレス認証のトークンについて言うと、アクセストークンやリフレッシュトークン <sup>[4]</sup> などのトークンのタイプを区別する必要があります。アクセストークンは保護されたりソースへのアクセスに使用され、存続期間は短くあるべきです。リフレッシュトークンは主に更新されたアクセストークンを取得するために使用されます。存続期間はかなり長くなりますが、期限もあります。さもなければ、その漏洩によりシステムが不正使用される可能性があります。

トークンの有効期限の正確な値はアプリケーションの要件と能力により異なります。JWT トークンリフレッシュのサンプルコードを以下に示します。
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

#### 動的解析

動的解析は効率的な選択肢です。傍受プロキシを使用してセッションタイムアウトが実行時に機能しているかどうかを確認することは簡単です。これはテストケース「ログアウト機能のテスト」に似ていますが、タイムアウト機能が発動するために必要な一定時間をアイドル状態のままにする必要があります。この条件を満たしたら、クライアント側とサーバー側でセッションが実際に終了することを確認する必要があります。

以下の手順を使用して、セッションタイムアウトが適切に実装されているかどうかを確認します。
1. アプリケーションにログインする。
2. アプリケーション内で認証を必要とするいくつかの操作を行う。
3. セッションが期限切れになるまで、アプリケーションをアイドル状態のままにする (テストの目的では、手頃なタイムアウトを設定し、後の最終バージョンで修正する) 。

傍受プロキシ (Burp Repeater など) を使用して手順2で実行した操作のひとつを再送します。この目的はセッションが期限切れとなった際に無効にされたセッション ID でリクエストをサーバーに送信することです。
セッションタイムアウトがサーバー側で正しく設定させている場合は、エラーメッセージまたはログインページへのリダイレクトがクライアントに返送されます。一方で、手順2と同じレスポンスがある場合、このセッションはまだ有効であり、セッションタイムアウトは正しく設定されていないことを意味します。
詳細は OWASP Web Testing Guide (OTG-SESS-007) <sup>[1]</sup> を参照ください。

#### 改善方法

ほとんどのフレームワークにはセッションタイムアウトを設定するパラメータがあります。このパラメータはフレームワークのドキュメントで指定されているベストプラクティスに応じて設定すべきです。ベストプラクティスのタイムアウト設定は、アプリケーションの機密性とその使用例に応じて、10分から2時間の間で遷移します。

#### 参考情報

##### OWASP Mobile Top 10 2016
* M4 - Insecure Authentication - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS
* 4.8: "Sessions and server side signed tokens are terminated at the remote endpoint after a predefined period of inactivity."

##### CWE
- CWE-613 - Insufficient Session Expiration

##### その他
* [1] OWASP Web Application Test Guide (OTG-SESS-007) - https://www.owasp.org/index.php/Test_Session_Timeout_(OTG-SESS-007)
* [2] OWASP Session management cheatsheet - https://www.owasp.org/index.php/Session_Management_Cheat_Sheet
* [3] RFC 7519 - https://tools.ietf.org/html/rfc7519#section-4.1.4
* [4] Refresh tokens & access tokens - https://auth0.com/blog/refresh-tokens-what-are-they-and-when-to-use-them/


### 2要素認証とステップアップ認証のテスト

#### 概要

モバイルアプリにログインする場合、二要素認証 (2FA) が標準になりつつあります。通常、最初の要素は資格情報 (ユーザー名/パスワード) で、次の要素には SMA 経由で送信されるワンタイムパスワード (OTP) が続きます。2FA の重要な側面は以下のカテゴリのうち二つの異なる要素を使用することです。
* あなたが持っているもの：これにはハードウェアトークンなどの物理オブジェクト、X.509 証明書などのデジタルオブジェクト (エンタープライズ環境の場合) 、モバイルフォン自体で生成されるソフトウェアトークンがあります。
* あなたが知っていること：これにはパスワードなどのユーザーだけが知っている秘密があります。
* あなたの何か：これには TouchID などのユーザーを識別する生体的属性があります。

機密データや重要な機能へのアクセスを提供するアプリケーションでは、より強力な認証メカニズムでユーザーに再認証を要求する可能性があります。例えば、生体認証 (TouchID など) を介して銀行業務アプリにログインした後、ユーザーは銀行振込を実行するために OTP を介していわゆる「ステップアップ認証」を行う必要があるかもしれません。

ステップアップ認証の主な利点はユーザーの利便性が向上することです。ユーザーは必要な場合にのみ追加の要素での認証を求められます。


#### 静的解析

サーバー側ソースコードが利用可能である場合、まず第二要素やステップアップ認証がどのように使用および実施されているか特定します。その後、機密および特権の情報および機能を持つすべてのエンドポイントを特定します。これらは保護が必要なものです。そのアイテムにアクセスする前に、アプリケーションはユーザーが 2FA またはステップアップ認証をすでにパスしており、エンドポイントにアクセスすることが許可されていることを確認する必要があります。

2FA やステップアップ認証はゼロから実装すべきではなく、代わりにこの機能を提供する利用可能なライブラリの上に構築すべきです。サーバー側で使用されるライブラリを特定し、利用可能な API や機能がベストプラクティスに応じて使用されているかどうか検証する必要があります。

例えば、GoogleAuth <sup>[2]</sup> などのサーバー側ライブラリを使用します。このようなライブラリはタイムベースのワンタイムパスワードアルゴリズム (TOTP) を使用して追加の要素を実装する広く受け入れられたメカニズムに依存しています。TOTP は暗号アルゴリズムであり、クライアントとサーバー間の共有された共通鍵と現在の時刻から OTP を計算します。作成された OTP は短い時間 (通常 30 から 60 秒) のみ有効です。

サーバー側コードでライブラリを使用する代わりに、例のような利用可能なクラウドソリューションも使用できます。

- Google Authenticator <sup>[2]</sup>
- Microsoft Authenticator <sup>[3]</sup>
- Authy <sup>[4]</sup>

実装がサーバー側またはクラウドプロバイダを使用して行われているかどうかにかかわらず、TOTP アプリを開始して、ユーザーの認証を待っているアプリに入力する必要のある OTP を表示する必要があります。

ローカルの生体認証を追加の要素とするには、「生体認証のテスト」のテストケースを確認します。

#### 動的解析

まず、ユーザーがステップアップ認証またはアプリ内の 2FA でのみアクセスできるすべての特権エンドポイントを調べます。エンドポイントに送信されるこれらのリクエストのすべてについて、傍受プロキシを使用して、ネットワークトラフィックをキャプチャします。次に、まだ 2FA やステップアップ認証で昇格していないトークンまたはセッション情報でリクエストを再生します。データは 2FA またはステップアップ認証の後でのみ利用可能となるべきですが、エンドポイントが依然としてリクエストされたデータを返送している場合には、エンドポイントで認証チェックが正しく実装されていません。

記録されたリクエストは認証情報を提供することなしでも再生して、認証メカニズムの完全なバイパスをチェックします。

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
