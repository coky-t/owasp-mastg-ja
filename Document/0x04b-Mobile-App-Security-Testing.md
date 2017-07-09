## モバイルアプリのセキュリティテスト

セキュリティ業界では「モバイルアプリペネトレーションテスト」、「モバイルアプリセキュリティレビュー」などのさまざまな用語が使用されています (何らかの不一致があります) 。このガイドでは、静的解析や動的解析を使用してモバイルアプリのセキュリティを評価するための包括的なフレーズとして「モバイルアプリのセキュリティテスト」を使用します。往々にして (必ずしもそうとは限りませんが) これはモバイルアプリで使用されるサーバー側 API だけでなく、クライアント・サーバーアーキテクチャ全体も包括するより大きなセキュリティ監査やペネトレーションテストのコンテキストで行われます。

考慮すべき重要な点は以下のとおりです。

- モバイルアプリの「ペネトレーションテスト」の話はあまり意味がありません。何もペネトレートしていないためです。

- モバイルアプリに関する限り、ホワイトボックステストとブラックボックステストの間に違いはありません。あなたは常にコンパイルされたアプリにアクセスすることができ、一度バイトコードやバイナリコードを読むこと (または逆コンパイラを使用すること) を学ぶと、コンパイルされたアプリを持つこととソースコードを持つことはほぼ同じになります。

このガイドでは、二つの異なるコンテキストでのモバイルアプリのセキュリティテストについて説明します。最初のひとつは「古典的な」セキュリティテストで、開発ライフサイクルの終わりに向かって行われます。ここでは、テスト担当者は最終版に近いバージョンのアプリまたは出荷準備バージョンのアプリにアクセスし、セキュリティの問題を特定し、(通常は壊滅的な) レポートを作成します。もうひとつは、ソフトウェア開発ライフサイクルの初期段階におけるセキュリティテストの自動化です。どちらの場合でも、同じ基本要件とテストケースが適用されますが、高レベルの方法論およびクライアントとの対話のレベルに大きな違いがあります。

### セキュリティテストの従来の方法

以下のセクションではセキュリティテストの中で OWASP モバイルアプリケーションのセキュリティチェックリストとテストガイドを使用する方法について説明します。それは四つのセクションに分かれています。

* **準備** - セキュリティテストの範囲を定義します。どのセキュリティコントロールが適用可能か、開発チームや組織がテストについてどのような目標を持っているか、テストのコンテキストで機密データとみなされるものは何かなどです。
* **情報収集** - アプリの **環境** と **アーキテクチャ** のコンテキストを分析して、アプリの一般的なコンテキストの理解を得ます。
* **脅威モデリング** - 初期段階に収集された情報を用いて、最も可能性の高い、または最も深刻である脅威を特定します。したがって、セキュリティテスト担当者からもっとも注目を集めるべきです。テスト実行で使用されるテストケースを生成します。
* **脆弱性解析** - 事前に作成されたテストケースを使用して脆弱性を特定します。静的手法、動的手法、フォレンジック手法があります。

### 準備

テストを行う前に、テストするための MASVS<sup>[1]</sup> のセキュリティレベルを何にするか合意に達する必要があります。セキュリティ要件は理想的には SDLC の開始時に決定すべきですが、必ずしもそうであるとは限りません。また、異なる組織ではセキュリティニーズが異なり、テスト活動に投じるリソース量も異なります。MASVS Level 1 (L1) のコントロールはすべてのモバイルアプリに適用されますが、テクニカルステークホルダおよびビジネスステークホルダが L1 および Level 2 (L2) MASVS コントロールのチェックリスト全体を確認し、適切なレベルのテストカバレッジに合意することをお勧めします。

組織やアプリケーションは特定の地域でさまざまな規制や法的義務を負う可能性があります。アプリが機密データを処理しない場合でも、業界の規制や地域の法律により L2 要件に関連するものがあるかどうかを検討することが重要です。例えば、二要素認証 (2FA) は金融アプリに対して義務付けられ、各国の中央銀行や金融監督庁により強制されます。

SDLC の最初に定義されるセキュリティの目標やコントロールはステークホルダのディスカッションの中でレビューされることもあります。コントロールの中には MASVS コントロール に従うものもあれば、組織やアプリケーションに固有のものもあります。

![Preparation](Images/Chapters/0x03/mstg-preparation.png)

すべての関係者は決定事項とチェックリストの範囲に合意する必要があります。これは、手動で行われるか自動で行われるかに関わらず、すべてのセキュリティテストのベースラインを定義しています。

#### 機密データの特定

機密情報の分類は業界や国によって異なる場合があります。法的義務や市民的義務を超えて、組織は機密データとみなされるものについてより厳格な見解を持ち、機密情報とみなされるものを明確に定義するデータ分類ポリシーを持つことがあります。

データにアクセスできる一般的な状態は三つあります。

* **休止中** - データがファイルやデータストアに格納されているとき
* **使用中** - アプリケーションがアドレス空間にデータをロードしたとき
* **転送中** - 使用しているプロセスの間でデータが送信されたとき - 例、IPC 中。

それぞれの状態に適用される調査の度合いはデータの重要度やアクセスの可能性に依存する可能性があります。例えば、悪意のある人がモバイルデバイスに物理的にアクセスする可能性が高いため、アプリケーションメモリに保持されているデータはウェブサーバー上のデータにコアダンプを介してアクセスされるリスクが高くなる可能性があります。

利用可能なデータ分類ポリシーがない場合、以下の種類の情報は一般的に機密であるとみなされます。

* ユーザー認証情報 (資格情報、PIN など)。
* なりすましにより悪用されるかのうせいのある個人識別情報 (PII) : 社会保障番号、クレジットカード番号、銀行口座番号、健康保険情報。
* 侵害された場合、風評被害や金銭的なコストにつながる機密性の高いデータ。
* 法令またはコンプライアンス上の理由により保護される必要のあるデータ。
* 最後に、アプリケーションやそれに関連するシステムにより生成され、他のデータやシステムを保護するために使用される技術データも、機密情報とみなす必要があります (暗号化鍵など) 。

そのようなものとみなされる具体的な定義がなければ、機密データの漏洩を検出することは不可能な場合があります。そのためそのような定義はテストの前に合意する必要があります。

### 情報収集

情報収集には、アプリのアーキテクチャ、それが提供するビジネスユースケース、それが動作するコンテキストについての情報の収集が含まれます。そのような情報は「環境」と「アーキテクチャ」に大別できます。

#### 環境情報

環境情報は以下を理解することと関係します。

* **組織がアプリのために持っている目標** - アプリが行おうとしているものは、ユーザーがそれとやりとりしようとする方法を形作り、一部の領域では他よりも攻撃者がターゲットにする可能性が高くなります。
* **それらが動作する業界** - 特定の業界では異なるリスクプロファイルを持ち、特定の攻撃ベクトルにさらされる度合いが増減する可能性があります。
* **ステークホルダと投資家** - アプリに興味を持っているのは誰か、責任を持っているのは誰かを理解します。
* **内部プロセス、ワークフロー、組織構造** - 組織固有の内部プロセスおよびワークフローはビジネスロジックを悪用する機会をもたらす可能性があります <sup>[2]</sup> 。

#### アーキテクチャ情報

アーキテクチャ情報は以下を理解することと関係します。

* **アプリ:** - アプリがデータにアクセスしそれをプロセス内で管理する方法、他のリソースとの通信方法、ユーザーセッションの管理方法、脱獄済み電話やルート化された電話上で実行していることを検出および反応するかどうか。
* **オペレーティングシステム:** - アプリが実行されるオペレーティングシステムとバージョン (新しい Android または iOS のみに限定されているか、以前の OS バージョンの脆弱性を気にする必要があるかなど) 、モバイルデバイス管理 (MDM <sup>[3]</sup>) コントロールを備えたデバイス上で動作することが期待されているか、アプリに関連する可能性がある OS 脆弱性は何か。
* **ネットワーク:** - セキュアなトランスポートプロトコル (TLS など) が使用されるか、ネットワークトラフィック暗号化は強力な鍵および暗号アルゴリズム (SHA-2 など) で保護されているか、エンドポイントの検証に証明書ピンニングが使用されているか、など。
* **リモートサービス:** - アプリが使用するリモートサービスは何か、それらが侵害された場合クライアントは侵害される可能性があるか。

### 脅威モデリング

脅威モデリングは情報収集フェーズの結果を使用して、どのような脅威の可能性があるか否かを判断し、後のステージで実行されるテストケースを生成します。脅威モデリングは一般的な SDLC の重要な部分であり、理想的にはペネトレーションテストの直前ではなく、開発を通して実行する必要があります。

一般的な脅威モデリングのガイドラインは OWASP により定義されており <sup>[3]</sup> 、通常はモバイルアプリに適用可能です。

<!-- are there any threat Modeling techniques specially applicable to mobile apps? -->

### 脆弱性解析

#### 静的解析

静的解析を実行する際には、モバイルアプリのソースコードを解析して、セキュリティコントロールの十分かつ正確な実装を保証します。暗号化やデータストレージメカニズムなどの重要なコンポーネントに焦点を当てます。テスト担当者が直面する可能性のあるコード量により、静的解析の理想的なアプローチはコードを自動的にスキャンするツールを使用することと手動コードレビューを組み合わせたものであるべきです。

このアプローチにより、あなたは両方の世界から最高のものを得ることができます。自動スキャンでは「低い位置にぶら下がった果実」 (訳注：「簡単に解決できる問題」の比喩) とよばれるものを取得できます。スキャンエンジンとその (事前定義された) ルールはコード内の多くの一般的な脆弱性を検知できます。手動コードレビューは特定のビジネスや使用状況を念頭においてコードベースを探索します。関連性とカバレッジが向上します。

#### 自動コード解析

自動静的解析の中では、ツールは事前定義された一連のルールや業界のベストプラクティスを遵守しているかどうかについてソースコードをチェックします。解析手法を使用することは標準的な開発のプラクティスです。モバイルアプリケーションのソースコードをレビューおよび検査して、バグや実装エラーを検出します。

自動静的解析ツールは手動コードレビューおよびインスペクションプロセスを支援します。ツールは一般的に調査結果や警告の一覧を表示し、検出されたすべての違反にフラグを立てます。自動静的ツールはさまざまな種類があります。ビルドされたコードに対してのみ実行するもの、ソースコードを与える必要があるもの、統合開発環境 (IDE) のライブ解析プラグインとして動作するもの <sup>[4]</sup> 。理想的にはこれらのツールは開発プロセスの中で使用すべきですが、ソースコードレビューの中でも役に立ちます。

一部の静的コード解析ツールは要求される基本的なルールやセマンティクスの深い知識をカプセル化して特定の種類の解析を実行しますが、報告された違反が誤検知であるかどうかを特定するために専門家が必要とされます。

特にツールが対象環境に対して適切に構成されていない場合、自動静的解析は多数の誤検知を生み出す可能性があることに注意する必要があります。最初に限定されたクラスの脆弱性に対してのみスキャンを実行することをお勧めします。結果の量に圧倒されることを避けるためです。

静的解析のためのツールの完全なリストは「テストツール」の章にあります。

#### 手動コード解析

手動コード解析では、人間のコードレビュー担当者がモバイルアプリケーションのソースコードを調べ、セキュリティ上の脆弱性を特定します。これは、基本的にはソースコードリポジトリ内をキーワードで grep で検索して潜在的に脆弱なコードパターンの使用を特定することであり、拡張として IDE プラグインを使用したライブ解析があります。IDE は基本的なコードレビュー機能を提供し、レビュープロセスを支援するさまざまなツールを通じて拡張できます。

手動コードレビューの中で、コードベースをスキャンしてセキュリティ上の脆弱性の重要な指標を探します。これは "Crawling Code" <sup>[9]</sup> とも呼ばれ、関数や API 内で使用される特定のキーワードを検索することにより実行されます。例えば、DES, MD5, Random などの暗号化文字列、executeStatement や executeQuery などのデータベース関連の文字列も興味深い主要な指標となりえます。

手動コードレビューと自動コード解析ツールの使用の間の主な相違点は、手動コードレビューがビジネスロジック、標準規約の違反、設計上の欠陥での脆弱性を特定することに優れています。特にコードが技術的にセキュアであるが論理的に欠陥があるような状況です。このようなシナリオは自動コード解析ツールでは検出されない可能性があります。

手動コードレビューはモバイルアプリケーションで使用される言語とフレームワークの両方に精通した専門家のコードレビュー担当者を要求します。モバイルアプリケーションのソースコードで使用されるテクノロジのセキュリティ実装を深く理解していることが不可欠です。その結果、レビュー担当者にとって時間がかかり、遅く、面倒です。多くの依存関係を持つ巨大なコードベースの場合には特にそうです。

#### 動的解析

動的解析では、アプリをリアルタイムにさまざまな状況で実行することによりテストおよび評価することに重点を置いています。動的解析の主な目的は、プログラムを実行する中でセキュリティ上の脆弱性や弱点を見つけることです。動的解析はモバイルアプリケーションのバックエンドサービスや API に対しても実行され、そのリクエストやレスポンスパターンを解析する必要があります。

通常、動的解析を実行して、転送時のデータの開示、認証および認可の問題、サーバーの構成エラーを防止するための十分なセキュリティ機構があるかどうかをチェックします。

##### 動的解析の利点

* ソースコードにアクセスする必要はありません
* モバイルアプリケーションがどのような動作を期待されるかを理解する必要はありません
* 静的解析ツールでは見逃す可能性のあるインフラストラクチャ、構成、パッチの問題を特定できます

##### 動的解析の欠点

* モバイルアプリケーションは特定のテストエリアを識別するために足跡を残す必要があるため、カバレッジのスコープが制限されます
* ツールがモバイルアプリケーションを実行し、リクエストとレスポンスのパターンマッチングを実行するため、実際の命令へのアクセスは実行されません

#### 実行時解析

-- TODO [Describe Runtime Analysis : goal, how it works, kind of issues that can be found] --

#### トラフィック解析

Dynamic analysis of the traffic exchanged between client and server can be performed by launching a Man-in-the-middle (MITM) attack. This can be achieved by using an interception proxy like Burp Suite or OWASP ZAP for HTTP traffic.  

* Configuring an Android Device to work with Burp - https://support.portswigger.net/customer/portal/articles/1841101-configuring-an-android-device-to-work-with-burp
* Configuring an iOS Device to work with Burp - https://support.portswigger.net/customer/portal/articles/1841108-configuring-an-ios-device-to-work-with-burp

In case another (proprietary) protocol is used in a mobile app that is not HTTP, the following tools can be used to try to intercept or analyse the traffic:
* Mallory - https://github.com/intrepidusgroup/mallory
* Wireshark - https://www.wireshark.org/

#### 入力ファジング

The process of fuzzing is to repeatedly feeding an application with various combinations of input value, with the goal of finding security vulnerabilities in the input-parsing code. There were instances when the application simply crashes, but also were also occasions when it did not crash but behave in a manner which the developers did not expect them to be, which may potentially lead to exploitation by attackers.  

Fuzzing, is a method for testing software input validation by feeding it intentionally malformed input. Below are the steps in performing the fuzzing:

* Identifying a target
* Generating malicious inputs
* Test case delivery
* Crash monitoring

Also refer to the OWASP Fuzzing guide<sup>[5]</sup>

Note: Fuzzing only detects software bugs. Classifying this issue as a security flaw requires further analysis by the researcher.

* **Protocol adherence** - for data to be handled at all by an application, it may need to adhere relatively closely to a given protocol (e.g. HTTP) or format (e.g. file headers). The greater the adherence to the structure of a given protocol or format, the more likely it is that meaningful errors will be detected in a short time frame. However, it comes at the cost of decreasing the test surface, potentially missing low level bugs in the protocol or format.

* **Fuzz Vectors**<sup>[6]</sup> - fuzz vectors may be used to provide a list of known risky values likely to cause undefined or dangerous behaviour in an app. Using such a list focuses tests more closely on likely problems, reducing the number of false positives and decreasing the test execution time.

### 一般的な落とし穴

#### Web アプリスキャナの誤検知

A typical reflected XSS attack is executed by sending a URL to the victim(s), which for example can contain a payload to connect to some exploitation framework like BeeF<sup>[2]</sup>. When clicking on it a reverse tunnel is established with the Beef server in order to attack the victim(s). As a WebView is only a slim browser, it is not possible for a user to insert a URL into a WebView of an app as no address bar is available. Also, clicking on a link will not open the URL in a WebView of an app, instead it will open directly within the default browser of the respective mobile device. Therefore, a typical reflected Cross-Site Scripting attack that targets a WebView in an app is not applicable and will not work.

If an attacker finds a stored Cross-Site Scripting vulnerability in an endpoint, or manages to get a Man-in-the-middle (MITM) position and injects JavaScript into the response, then the exploit will be sent back within the response. The attack will then be executed directly within the WebView. This can become dangerous in case:

* JavaScript is not deactivated in the WebView (see OMTG-ENV-005)
* File access is not deactivated in the WebView (see OMTG-ENV-006)
* The function addJavascriptInterface() is used (see OMTG-ENV-008)

In summary, a reflected Cross-Site Scripting is no concern for a mobile App, but a stored Cross-Site Scripting vulnerability or MITM injected JavaScript can become a dangerous vulnerability if the WebView if configured insecurely.

The same problems with reflected XSS also applied to CSRF attacks. A typical CSRF attack is executed by sending a URL to the victim(s) that contains a state changing request like creation of a user account or triggering a financial transaction. Just as with XSS, it is not possible for a user to insert a URL into a WebView of an app. Therefore a typical CSRF attack that targets a WebView in an app is not applicable.

The basis for CSRF attacks, access to session cookies of all browser tabs and attaching them automatically if a request to a web page is executed is not applicable on mobile platforms. This is the default behaviour of full blown browsers. Every app has, due to the sandboxing mechanism, it's own web cache and stores it's own cookies, if WebViews are used. Therefore a CSRF attack against a mobile app is by design not possible as the session cookies are not shared with the Android browser.

Only if a user logs in by using the Android browser (instead of using the mobile App) a CSRF attack would be possible, as then the session cookies are accessible for the browser instance.

#### 参考情報

* [1] MASVS - https://github.com/OWASP/owasp-masvs
* [2] Testing for Business Logic - https://www.owasp.org/index.php/Testing_for_business_logic
* [3] OWASP Application Threat Modeling - https://www.owasp.org/index.php/Application_Threat_Modeling
* [4] SecureAssist - https://www.synopsys.com/software-integrity/resources/datasheets/secureassist.html
* [5] OWASP Fuzzing Guide - https://www.owasp.org/index.php/Fuzzing
* [6] OWASP Testing Guide Fuzzing - https://www.owasp.org/index.php/OWASP_Testing_Guide_Appendix_C:_Fuzz_Vectors
