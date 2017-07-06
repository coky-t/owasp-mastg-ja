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

Intelligence gathering involves the collection of information about the architecture of the app, the business use cases it serves, and the context in which it operates. Such information may be broadly divided into `environmental` and `architectural`.

#### 環境情報

Environmental information concerns understanding:

* **The goals the organization has for the app** - what the app is supposed to do shapes the ways users are likely to interact with it, and may make some surfaces more likely to be targeted than others by attackers.   
* **The industry in which they operate** - specific industries may have differing risk profiles, and may be more or less exposed to particular attack vectors.
* **Stakeholders and investors** - understanding who is interested in or responsible for the app.
* **Internal processes, workflows and organizational structures** - organization-specific internal processes and workflows may create opportunities for business logic exploits<sup>[2]</sup>.

#### アーキテクチャ情報

Architectural information concerns understanding:

* **App:** - how the app accesses data and manages it in-process, how it communicates with other resources, manages user sessions, and whether it detects and reacts to running on jailbroken or rooted phones.
* **Operating System:** - what operating systems and versions does the app run on (e.g. is it restricted to only newer Android or iOS, and do we need to be concerned about vulnerabilities in earlier OS versions), is it expected to run on devices with Mobile Device Management (MDM<sup>[3]</sup>) controls, and what OS vulnerabilities might be relevant to the app.
* **Network:** - are secure transport protocols used (e.g. TLS), is network traffic encryption secured with strong keys and cryptographic algorithms (e.g. SHA-2), is certificate pinning used to verify the endpoint, etc.
* **Remote Services:** - what remote services does the app consume? If they were compromised, could the client by compromised?

### 脅威モデリング

Threat Modeling involves using the results of the information gathering phase to determine what threats are likely or severe, producing test cases that may be executed at later stages. Threat Modeling should be a key part of the general SDLC, ideally performed throughout development, rather than just before a penetration test.

General threat Modeling guidelines have been defined by OWASP<sup>[3]</sup>, and these are usually applicable to mobile apps.

<!-- are there any threat Modeling techniques specially applicable to mobile apps? -->

### 脆弱性解析

#### 静的解析

When executing static analysis, the source code of the mobile app(s) will be analysed to ensure sufficient and correct implementation of security controls, focusing on crucial components such as cryptographic and data storage mechanisms. Due to the amount of code a tester may be confronted with, the ideal approach for static analysis should be a mixture of using tools that scan the code automatically and manual code review.

Through this approach you can get the best out of both worlds. You can get the so called "low hanging fruits" through the automatic scan, as the scanning engine and its (predefined) rules can detect many common vulnerabilities in the code. A manual code review can explore the code base with specific business and usage contexts in mind, providing enhanced relevance and coverage.

#### 自動コード解析

During automatic static analysis, a tool will check the source code for compliance with a predefined set of rules or industry best practices. It is a standard development practice to use analytical methods to review and inspect the mobile application's source code to detect bugs and implementation errors.

The automatic static analysis tools will provide assistance with the manual code review and inspection process. The tool will typically display a list of findings or warnings and then flag all detected violations. Automatic static tools come in different varieties - some only run against built code, some just need to be fed with the source code and some run as live-analysis plugins in an Integrated Development Environments (IDE)<sup>[4]</sup>. Ideally these tools should be used during the development process, but can also be useful during a source code review.

Some static code analysis tools encapsulate a deep knowledge of the underlying rules and semantics required to perform the specific type of analysis, but still require a professional to identify whether a reported violation is a false positive or not.

It should be noted that automatic static analysis can produce a high number of false positives, particularly if the tool is not configured properly for the target environment. Initially executing the scan for only a limited class of vulnerabilities might be a good decision - to avoid getting overwhelmed by the volume of results.

A full list of tools for static analysis can be found in the chapter "Testing tools".

#### 手動コード解析

In manual code analysis, a human code reviewer will look through the source code of the mobile application, to identify security vulnerabilities. This can be as basic as searching with grep for key words within the source code repository to identify usages of potentially vulnerable code patterns, or as sophisticated as live-analysis using an IDE plugin. An IDE provides basic code review functionality and can be extended through different tools to assist in the reviewing process.

During a manual code review, the code base will be scanned to look for key indicators of security vulnerabilities. This is also known as "Crawling Code"<sup>[9]</sup> and will be executed by looking for certain keywords used within functions and APIs. For example, cryptographic strings like DES, MD5 or Random, or even database related strings like executeStatement or executeQuery are key indicators which may be of interest.

The main difference between a manual code review and the use of an automatic code analysis tool is that manual code review is better at identifying vulnerabilities in the business logic, standards violations and design flaws, especially in situations where the code is technically secure but logically flawed. Such scenarios are unlikely to be detected by any automatic code analysis tool.

A manual code review requires an expert human code reviewer who is proficient in both the language and the frameworks used in the mobile application. It is essential to have a deep understanding of the security implementation of the technologies used in the mobile application's source code. As a result it can be time consuming, slow and tedious for the reviewer; especially for large codebases with many dependencies.

#### 動的解析

In dynamic analysis the focus is on testing and evaluating an app by executing it in real-time, in different situations. The main objective of dynamic analysis is to find security vulnerabilities or weak spots in a program while it is running. Dynamic analysis should also be conducted against the backend services and APIs of mobile applications, where its request and response patterns can be analysed.

Usually, dynamic analysis is performed to check whether there are sufficient security mechanisms in place to prevent disclosure of data in transit, authentication and authorization issues and server configuration errors.

##### 動的解析の利点

* Does not require access to the source code
* Does not need an understanding of how the mobile application is supposed to behave
* Able to identify infrastructure, configuration and patch issues that Static Analysis tools may miss

##### 動的解析の欠点

* Limited scope of coverage because the mobile application must be footprinted to identify the specific test area
* No access to the actual instructions being executed, as the tool exercises the mobile application and conducts pattern matching on requests and responses

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
