# テストプロセスと技法

## モバイルアプリセキュリティテスト手法

-- TODO [Describe Mobile Security Testing methodology] --

The context of mobile security testing is a conjunction of multiple different tier of components: **app**, **system**, **communication** and **back-end server**. These four high-level components will be the main attack surface for a mobile security test.   

* **App:**  Insecure data storage, poor resiliency against reverse engineering etc.
* **System:** Any system API to which sensitive info is sent. E.g. Tampering with the system HTTP client might give access to the whole communication, even when SSL with certificate pinning is used.
* **Communication:** Usage of insecure or unencrypted communication channel, missing SSL certificate pinning etc.
* **Back-end Servers:** Flawed authentication and session management, vulnerable server side functions etc.

### Different Types of Mobile Apps

The following section is a brief introduction to the 3 different types of mobile applications, namely the (1) Native App, (2) Hybrid App and (3) Web App. Before we dive into them, it is essential to first understand what a mobile app is.

#### Mobile App

The term `mobile app` refers to applications (self-contained computer programs), designed to execute and enhance the functionality of a mobile device. In this guide we will focus on the mobile apps designed to run on Android and iOS operating systems, as cumulatively they take more than 99% of the market share<sup>[12]</sup>. Due to the expansion of these operating systems to other device types, like smart watches, TVs, cars, etc. a more general term `app` is more appropriate. Nevertheless, for historic reasons, both terms are used interchangeably to refer to an application that can run on some of these systems, regardless of the exact device type.

Today, mobile internet usage has surpassed desktop usage for the first time in history and mobile apps are the most widespread kind of applications<sup>[10]</sup>.

#### Native App

Most operating systems, including Android and iOS, come with set of high-level APIs that can be used to develop applications specifically for that system. Such applications are called `native` for the system for which they have been developed. Usually, when discussing about `mobile app`, the assumption is that it is a `native app`, that is implemented in a particular programming language for either iOS (Objective-C or Swift) or Android (Java).

Native mobile apps provide fast performance and a high degree of reliability. They usually adhere to the design principles (e.g. Android Design Principles<sup>[13]</sup>), providing a more consistent UI, compared to `hybrid` and `web` apps. Due to their close integration with the operating system, native apps have access to almost every component of the device (camera, sensors, hardware backed key stores, etc.)

Please note that there is a little ambiguity when discussion `native` apps for Android. Namely, Android provides two sets of APIs to develop against, Android SDK and Android NDK. The SDK (or Software Development Kit) is a Java API and is the default API against which applications are built. The NDK (or Native Development Kit) is a C/C++ based API used for developing only parts of the application that require specific optimization, or can otherwise benefit from lower level API. Normally, you can only distribute apps build with the SDK, which potentially can have parts implemented against NDK. Therefore we say that Android `native **apps**` (build against SDK) can have `native **code**` (build against NDK).

Biggest downside of native apps is that they target only one specific platform. To build the same app for both Android and iOS, one needs to maintain two independent code bases.

#### Web App

Mobile Web apps, or simply Web apps, are websites designed to look and feel like a native app. They run in a browser and are usually developed in HTML5. Normally, both Android and iOS allow for launcher icons to be created out of bookmarked Web apps, which simply run the default web browser and load the bookmarked app.

Web apps have limited integration with the components of the device and usually have a noticeable difference in performance. Since they typically target multiple platforms, their UI does not follow some of the design principles users are used to. Their biggest advantage is the price for supporting multiple platforms (only slight adaptation in the UI can server well most desktop and mobile operating systems), as well as their flexibility for delivering new content (as they are not delivered over an official application store, which sometimes take weeks to distribute through).

#### Hybrid App

Hybrid apps attempt to fill the gap between native and web apps. Namely, hybrid apps are (distributed and executed as) native apps, that have majority of their content implemented on top of web technologies, running in an embedded web browser (web view). As such, hybrid apps inherit some of the pros and cons of both native and web apps.

A web-to-native abstraction layer enables access to device capabilities for hybrid apps that are not accessible to mobile web applications. Depending on the framework used for developing, one code base can result in multiple applications, targeting separate platforms, with a UI closely resembling that of the targeted platform. Nevertheless, usually significant effort is required to exactly match the look and feel of a native app.

Following is a non-exhaustive list of more popular frameworks for developing Hybrid Apps:

* Apache Cordova - https://cordova.apache.org/
* Framework 7 - http://framework7.io/
* Ionic - https://ionicframework.com/
* jQuery Mobile - https://jquerymobile.com/
* Native Script - https://www.nativescript.org/
* Onsen UI - https://onsen.io/
* React Native - http://www.reactnative.com/
* Sencha Touch - https://www.sencha.com/products/touch/

### テストプロセス

The following sections will show how to use the OWASP mobile application security checklist and testing guide during a security test.

#### Preparation - Defining The Baseline

First of all, you need to decide what security level of the MASVS to test against. The security requirements should ideally have been decided at the beginning of the SDLC - but unfortunately we are not living in an ideal world. At the very least, it is a good idea to walk through the checklist, ideally with an IT security representative of the enterprise, the app stakeholders of the project and make a reasonable selection of Level 2 (L2) controls to cover during the test.

The controls in MASVS Level 1 (L1) are appropriate for all mobile apps - the rest depends on the threat model and risk assessment for the particular app. Discuss with the app stakeholders to understand what are the requirements that are applicable and which are the ones that should be deemed out of scope for the scope of testing, perhaps due to business decisions or company policies. Also consider whether some L2 requirements may be needed due to industry regulations or local laws - for example, 2-factor-authentation (2FA) may be obligatory for a financial app, as enforced by the respective country's central bank and/or financial regulatory authority.

If security requirements were already defined during the SDLC, even better! Ask for this information and document it on the front page of the Excel sheet ("dashboard"). More guidance on the verification levels and guidance on the certification can be found in the [MASVS](https://github.com/OWASP/owasp-masvs).

![Preparation](Images/Chapters/0x03/mstg-preparation.png)

All involved parties need to agree on the decisions made and on the scope in the checklist, as this will present the baseline for all security testing, regardless if done manually or automatically.

#### Mobile App Security Testing

During a manual test, one can simply walk-through the applicable requirements down the checklist, one-by-one. For a detailed testing procedures, simply click on the link provided in the "Testing Procedure" column. These links will bring you to the respective chapter in the OWASP Mobile Security Testing Guide (MSTG), where detailed steps and examples are listed for reference and guidance purposes.

Also important is to note that the OWASP Mobile Security Testing Guide (MSTG) is still "Work In Progress" and being updated even as you are reading this paragraph, therefore, some test cases may not have been written yet or may be in a draft status. (Ideally, if you discover any missing content, you could contribute it yourself).

![The checklist. Requirements marked with "L1" should always be verified. Choose either "Pass" or "Fail" in the "Status" column. The links in the "Testing Procedure" column lead to the OWASP Mobile Security Testing Guide.](Images/Chapters/0x03/mstg-test-cases.png)

The status column can have one of the following three different values, that need to be filled out:

* **Pass:** Requirement is applicable to mobile app and implemented according to best practices.
* **Fail:** Requirement is applicable to mobile app but not fulfilled.
* **N/A:** Requirement is not applicable to mobile app.

#### Reverse Engineering Resiliency Testing

*Resiliency testing* is a new concept introduced in the OWASP MASVS and MSTG. This kind of testing can be used if the app implements defenses against specific client-side threats.. As we know, such protection is never 100% effective. The goal in resiliency testing is to identify glaring holes in the protection scheme and verify that the expectations as to its effectiveness are met. The assessment methodology is described in detail in the appendix "[Assessing Anti-Reversing Schemes](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x07d-Assessing-Anti-Reverse-Engineering-Schemes.md)".

#### Reporting

The checklist itself can be used as a report as it lists down in detail what test cases have been included and verified in the tests and ideally also shows evidence in case a test fails. Also the first page should then be filled out, to include all the meta information needed for a report.

#### The Management Summary

A spider chart is generated on the fly according to the results of the requirements for both supported platforms (Android and iOS) in the "Management Summary" tab. You can use this in your report to point out areas that need improvement, and visualize progress over time.

![Management Summary - Spider Chart](Images/Chapters/0x03/mstg-spiderchart.png)

The spider chart visualizes the ratio of passed and failed requirements in each domain. As can be seen above all requirements in "V3: Cryptography Verification Requirements" were set to "pass", resulting in a value of 1.00. Requirements that are set to N/A are not included in this chart.

A more detailed overview can also be found in the "Management Summary" tab. This table gives an overview according to the eight domains and breaks down the requirements according to it's status (Passed, Failed or N/A). The percentage column is the ratio from passed to failed requirements and is the input for the spider chart described above.

![Management Summary - Detailed Overview](Images/Chapters/0x03/mstg-detailed-summary.png)


## 脆弱性解析技法

### 静的解析

When executing a static analysis, the source code of the mobile App(s) will be analyzed to ensure sufficient and correct implementation of security controls, specifically on crucial components such as cryptographic and data storage mechanisms. Due to the amount of code a tester will be confronted with, the ideal approach for static analysis should be a mixture of using tools that scan the code automatically and manual code review.

Through this approach you can get the best out of both worlds. You can get the so called "low hanging fruits" through the automatic scan, as the scanning engine and the (predefined) rules can easily pick up vulnerable patterns in the code. The manual code review can proficiently make a deep dive into the various code paths to check for logical errors and flaws in the mobile application's design and architecture where automated analysis tools are not able to identify it properly as they mostly do not understand the big picture.

#### 自動コード解析

During an automatic static analysis, a tool will check the source code for compliance with a predefined set of rules or industry's best practices. It has been a standard development practice to use analytical methods to review and inspect the mobile application's source code to detect bugs and implementation errors.

The automatic static analysis tools will provide assistance with the manual code review and inspection process. The tool will typically display a list of findings or warnings and then flag all the instances which contains any forms of violations in terms of their programming standards. Automatic static tools come in different variations, some are only running when you can actually build the app, some just need to be feed with the source code and some are running as plugin in an Integrated Development Environments (IDE)<sup>[7] [8]</sup>. The latter one provides assistance within your IDE in improving the security mechanisms in the mobile application code through a programmer-assisted way to correct the issues found. Ideally these tools should be used during the development process, but can also be useful during a source code review.

Some static code analysis tools encapsulate deep knowledge of the underlying rules and semantics required to perform the specific type of analysis, but still require a professional to identify if it's a false positive or not.

It should be noted that automatic static analysis can produce a high number of false positives, if the tool is not configured properly to the target environment. Executing the scan only for certain vulnerability classes might be a good decision for the first scan to not get overwhelmed with the results.

In the role of a penetration testing engagement, the use of automatic code analysis tools can be very handy as it could quickly and easily provide a first-level analysis of source code, to identify the low hanging fruits before diving deeper into the more complicated functions, where it is essential to thoroughly assess the method of implementation in varying contexts.

A full list of tools for static analysis can be found in the chapter "Testing tools".

#### 手動コード解析

In manual code analysis, a human code reviewer will be looking through the source code of the mobile application, to identify security vulnerabilities. This can be as basic as from crawling the code by executing grep on key words within the source code repository to identify usages of potentially vulnerable code patterns, to the usage of an Integrated Development Environment (IDE). An IDE provides basic code review functionality and can be extend through different tools to assist in reviewing process.

During a manual code review, the code base will be scanned to look for key indicators wherein a possible security vulnerability might reside. This is also known as "Crawling Code"<sup>[9]</sup> and will be executed by looking for certain keywords used within functions and APIs. For example, cryptographic strings like DES, MD5 or Random, or even database related strings like executeStatement or executeQuery are key indicators which are of interest in the process of crawling code.

The main difference between a manual code review and the use of any automatic code analysis tools is that in manual code review, it is better at identifying vulnerabilities in the business logic, standards violations and design flaws, especially in the situations where the code is technically secure but logically flawed. In such scenarios, the code snippet will not be detected by any automatic code analysis tool as an issue.

A manual code review requires an expert human code reviewer who is proficient in both the language and the frameworks used in the mobile application. This is essential to have a deep understanding of the security implementation of the technologies used in the mobile application's source code. As a result it can be time consuming, slow and tedious for the reviewer; especially when mobile application source code has a large number of lines of code.

### 動的解析

In a Dynamic Analysis approach, the focus is on testing and evaluation of an app by executing it in a real-time manner, under different stimuli. The main objective of a dynamic analysis is to find the security vulnerabilities or weak spots in a program while it is running. Dynamic analysis is conducted against the backend services and APIs of mobile applications, where its request and response patterns would be analysed.

Usually, dynamic analysis is performed to check whether there are sufficient security mechanisms being put in place to prevent disclosure of data in transit, authentication and authorization issues, data validation vulnerabilities (e.g. cross-site scripting, SQL injection, etc.) and server configuration errors.

#### Pros of Dynamic Analysis

* Does not require to have access to the source code
* Does not need to understand how the mobile application is supposed to behave
* Able to identify infrastructure, configuration and patch issues that Static Analysis approach tools will miss

#### Cons of Dynamic Analysis

* Limited scope of coverage because the mobile application must be footprinted to identify the specific test area
* No access to the actual instructions being executed, as the tool is exercising the mobile application and conducting pattern matching on the requests and responses

#### 実行時解析

-- TODO [Describe Runtime Analysis : goal, how it works, kind of issues that can be found] --

#### トラフィック解析

Dynamic analysis of the traffic exchanged between client and server can be performed by launching a Man-in-the-middle (MITM) attack. This can be achieved by using an interception proxy like Burp Suite or OWASP ZAP for HTTP traffic.  

* Configuring an Android Device to work with Burp - https://support.portswigger.net/customer/portal/articles/1841101-configuring-an-android-device-to-work-with-burp
* Configuring an iOS Device to work with Burp - https://support.portswigger.net/customer/portal/articles/1841108-configuring-an-ios-device-to-work-with-burp

In case another (proprietary) protocol is used in a mobile app that is not HTTP, the following tools can be used to try to intercept or analyze the traffic:
* Mallory - https://github.com/intrepidusgroup/mallory
* Wireshark - https://www.wireshark.org/

#### 入力ファジング

The process of fuzzing is to repeatedly feeding an application with various combinations of input value, with the goal of finding security vulnerabilities in the input-parsing code. There were instances when the application simply crashes, but also were also occations when it did not crash but behave in a manner which the developers did not expect them to be, which may potentially lead to exploitation by attackers.  

Fuzz testing, is a method for testing software input validation by feeding it intentionally malformed input. Below are the steps in performing the fuzzing:

* Identifying a target
* Generating malicious inputs
* Test case delivery
* Crash monitoring

Also refer to the OWASP Fuzzing guide - https://www.owasp.org/index.php/Fuzzing

Note: Fuzzing only detects software bugs. Classifying this issue as a security flaw requires further analysis by the researcher.

### Vulnerability Analysis Considerations

#### Eliminating False Positives

##### Cross-Site Scripting (XSS)

A typical reflected XSS attack is executed by sending a URL to the victim(s), which for example can contain a payload to connect to some exploitation framework like BeeF<sup>[2]</sup>. When clicking on it a reverse tunnel is established with the Beef server in order to attack the victim(s). As a WebView is only a slim browser, it is not possible for a user to insert a URL into a WebView of an app as no address bar is available. Also, clicking on a link will not open the URL in a WebView of an app, instead it will open directly within the default browser of the respective mobile device. Therefore, a typical reflected Cross-Site Scripting attack that targets a WebView in an app is not applicable and will not work.

If an attacker finds a stored Cross-Site Scripting vulnerability in an endpoint, or manages to get a Man-in-the-middle (MITM) position and injects JavaScript into the response, then the exploit will be sent back within the response. The attack will then be executed directly within the WebView. This can become dangerous in case:

* JavaScript is not deactivated in the WebView (see OMTG-ENV-005)
* File access is not deactivated in the WebView (see OMTG-ENV-006)
* The function addJavascriptInterface() is used (see OMTG-ENV-008)

As a summary, a reflected Cross-Site Scripting is no concern for a mobile App, but a stored Cross-Site Scripting or injected JavaScript through MITM can become a dangerous vulnerability if the WebView in used is configured insecurely.

##### Cross-Site Request Forgery (CSRF)

The same problem described with reflected XSS also applied to CSRF attacks. A typical CSRF attack is executed by sending a URL to the victim(s) that contains a state changing request like creation of a user account or triggering a financial transaction. As a WebView is only a slim browser it is not possible for a user to insert a URL into a WebView of an app and also clicking on a link will not open the URL in a WebView of an App. Instead it will open directly within the browser of Android. Therefore a typical CSRF attack that targets a WebView in an app is not applicable.

The basis for CSRF attacks, access to session cookies of all browser tabs and attaching them automatically if a request to a web page is executed is not applicable on mobile platforms. This is the default behaviour of full blown browsers. Every app has, due to the sandboxing mechanism, it's own web cache and stores it's own cookies, if WebViews are used. Therefore a CSRF attack against a mobile app is by design not possible as the session cookies are not shared with the Android browser.

Only if a user logs in by using the Android browser (instead of using the mobile App) a CSRF attack would be possible, as then the session cookies are accessible for the browser instance.

## Classification of data

Classification of sensitive information can vary between different industries and countries. Therefore laws and regulations that are applicable to the app need to be known. This will become the basis of what sensitive information actually is in the context of the app.

Ideally the customer can share a data classification policy that is already considering all different requirements and clearly defines sensitive information. This will become then the baseline during testing. The data classification should be applicable to:

* Data at rest,
* Data in use and
* Data in transit

For example, regulations in Singapore for financial institutions has imposed a requirement to encrypt passwords and PINs explicitly, even though they are already transmitted via HTTPS. Even though this might not be a vulnerability from the point of view of a tester, it is mandatory to raise this finding as a compliance issue.

If no data classification policy is available, the following should be considered as sensitive information:

* User authentication information (credentials, PINs etc.),
* Personal Identifiable Information (PII) that can be abused for identity theft: Social security numbers, credit card numbers, bank account numbers, health information,
* Highly sensitive data that would lead to reputational harm and/or financial costs if compromised,
* Any data that must be protected by law or for compliance reasons.
* Finally any technical data, generated by the application or it's related systems, that is used to protect other data or the system, should also be considered as sensitive information (e.g. encryption keys).

Defining sensitive information before the test is important for almost all data storage test cases in Android and iOS, as otherwise the tester has no clear basis on what he might need to look for.

## ソフトウェア開発ライフサイクル内でのセキュリティテスト

ソフトウェア開発の歴史はそれほど古いわけではなく、チームがフレームワークなしでプログラムを開発するのをやめたことは容易に分かります。コードの行数が増えるにつれて、仕事をコントロール下におき、期限、品質、予算を満たすために最低限のルールが必要であるという事実を経験しています。

過去に最も広く採用された方法論は「ウォータフォール」系のものでした。開発は出発点から最終点に向かい、いくつかのステップを経て、あらかじめ定義された順序でそれぞれが行われました。特定のフェーズで何か間違いがあり、前のフェーズで何かを変更しなければならない場合、1つだけ後ろに戻ることができました。これはウォータフォールの方法論の重大な欠点でした。強力な利点 (構造を作り、労力をかける場所を明確にし、理解しやすくするなど) がありますが、欠点 (閉じられた部門で、遅く、専門チームでの開発など) もあります。

時が流れ、ソフトウェア開発は成熟し、競争も激化しており、市場の変化に迅速に対応して少ない予算でソフトウェア製品を生み出す必要が生じました。マーケットから生産まで組織全体の部門を解放し、小規模のチームが協力することでより少ない体制とするという考え方が人気を博しています。「アジャイル」のコンセプトが作成され(アジャイルの実装例としてスクラム、XP、RADがよく知られています)、より自律的なチームがより迅速に連携できるようになりました。

もともと、セキュリティはソフトウェア開発の一部ではありませんでした。それは追加として考えられ、ネットワークレベルの運用チームによって実行されました。これらのチームはソフトウェアプログラムのセキュリティが脆弱であることを補う方法を見つける必要がありました。しかし、これはソフトウェアプログラムが境界内に配置されている場合に可能でしたが、ウェブやモバイルテクノロジで生まれたソフトウェアを使用する新しい方法として、このコンセプトは時代遅れになりました。今日、多くの場合この新しいパラダイムで既存の脆弱性を補うことは非常に困難であるため、セキュリティはソフトウェア **内** で焼き尽くす必要があります。

ソフトウェア開発時にセキュリティを組み込む方法はセキュア SDLC (ソフトウェア開発ライフサイクル) を導入することです。セキュア SDLC はどの方法論や言語にも依存せず、ウォータフォールやアジャイルに組み込むことができます。使用しないという言い訳にはできません。この章では特に DevOps の世界についてアジャイルとセキュア SDLC に焦点を当てます。自律性と自動化を促進し、速いペースと協調的な方法でセキュアなソフトウェアを開発および提供する最先端の方法について以下で詳細を説明します。

### アジャイルと DevOps

#### DevOps

DevOps はソフトウェアの提供に関係するすべてのステークホルダ間の密接なコラボレーションに焦点を当てたプラクティスを指します。DevOps はソフトウェアを可能な限り迅速にユーザーにリリースできるという点で Agile の論理的進化です。コラボレーションの側面に加えて、ソフトウェアやインフラストラクチャの変更のビルド、テスト、リリースプロセスの大幅な自動化が促進されます。この自動化はデプロイメントパイプラインに組み込まれています。

##### -- Todo [Add deployment pipeline overview and description specific for mobile apps.] --

DevOps という言葉は開発チームと運用チームの間のコラボレーションのみを表現すると誤解されるかもしれませんが、DevOps の実践的先駆者である Gene Kim 氏は次のように述べています。「一見したところ、開発と運用の間に問題があるように見える。」「しかしテストがそこにあり、情報セキュリティの目的とシステムやデータを保護する必要がある。」これは管理者のトップレベルの関心事であり、DevOps 像の一部となっています。

言い換えると、今日あなたが「DevOps」という言葉を聞いたとき、DevOpsQATestInfoSec を考えているはずです。<sup>[16]</sup>

セキュリティはビジネスの成功にとってアプリケーションの全体的な品質、パフォーマンス、ユーザビリティと同じくらい重要です。開発サイクルが短縮されデプロイメントの頻度が増加するとしても、品質やセキュリティが当初から構築されていることを保証することは基本的なことです。

人間の視点から見ると、これはビジネス成果を達成するために協力する部門横断型チームを作ることによって達成されます。このセクションでは要件の開始から価値ある変更がユーザーに利用可能となるまでの開発ライフサイクル全体でのセキュリティの相互作用と統合に焦点を当てます。

### 一般的な考慮事項

* アップルストアのリリース時期
* 何がブラックリストされるのか、そしてどのようにそれを避けるのか。
* 一般的な問題：アプリは常に完全に削除されてから再インストールされることを確認する。そうでなければ再現が難しい問題があるかもしれない。
*

### SDLC 概要

#### SDLC の一般的な説明

使用されている開発手法が何であれ、SDLC は常に同じプロセスに従います。
* アプリケーションとそのコンポーネントのリスクアセスメントを実行して、リスクプロファイルを特定します。このリスクプロファイルは通常、組織のリスク対応やアプリケーションのスコープでの規制要件に依存します。リスクアセスメントは、アプリケーションがインターネットからアクセス可能であるか、どのような種類のデータが格納されるかなどの他の要因によっても影響されます。データ分類ポリシーはどのデータが機密とみなされるかを決定し、このデータをどのようにセキュアにする必要があるかを規定します。
* プロジェクトもしくは開発サイクルの開始時に、機能要件が収集されると同時に、**セキュリティ要件** をリスト化して明確にします。ユースケースを構築する際、**悪用ケース** を追加します。また、**セキュリティリスク** が分析され、プロジェクトの他のリスク(財務、マーケティング、製造など)と同様に処理されます。チーム(開発チームを含む)は必要に応じてセキュリティに関するトレーニングを行います(セキュアコーディングなど)。
* モバイルアプリケーションの場合、OWASP MASVS [todo: link to the other guide] を利用して、この最初のステップで実行されたリスクアセスメントに基づいてセキュリティ要件を決定することができます。特にアジャイルプロジェクトの場合、新しく追加された機能やアプリケーションで処理される新しいクラスのデータに基づいて一連の要件を反復してレビューすることが一般的です。
* アーキテクチャと設計の進行中には、基本的なアーティファクトである **脅威モデリング** を実行する必要があります。脅威モデルに基づいて、**セキュリティアーキテクチャ** が定義されます(ソフトウェアとハードウェアの両面で)。**セキュアコーディングルール** が確立され、使用される **セキュリティツール** のリストが作成されます。また、**セキュリティテスト** の戦略を明確にします。
* すべてのセキュリティ要件および設計上の考慮事項はアプリケーションライフサイクル管理システム (ALM) に保存する必要があります。一般的には課題追跡システムと呼ばれていて、開発/運用チームがセキュリティ要件が開発ワークフローに緊密に統合されていることを確認するために使用します。セキュリティ要件には、開発者がすばやく参照できるように、使用されているプログラミング言語でのソースコードスニペットも含まれていることが理想的です。セキュアコーディングガイドラインのもうひとつの戦略は、これらのコードスニペットのみを含むバージョン管理の専用のリポジトリを作成することです。word 文書や PDF にこれらのガイドラインを保存する従来のアプローチよりも多くの利点があります。
* 次のステップではソフトウェアを開発するための **コードレビュー** (一般的にはピアで)、自動化されたツールでの **静的解析**、セキュリティに特化した **単体テスト** を行います。
* それからリリース候補のテストを実施する待望の瞬間がきます。**ペネトレーションテスト** ("Pentest") では手動および自動化技術の両方を使用します。
* 最後に、ソフトウェアがすべてのステークホルダから **認定** された後、運用チームに移行して安全に生産に投入することができます。

下の図はすべてのフェーズとさまざまなアーティファクトを示しています。
-- TODO [Add a picture of a SDLC diagram that clarifies the description above] --

プロジェクトのリスクに基づいて、一部のアーティファクトを単純化する(またはスキップする)こともあれば追加することもあります(正式な中間承認、特定ポイントの文書化など)。**常に SDLC はソフトウェア開発にリスク削減をもたらすことを意図しており、これらのリスクを許容レベルまで減らすコントロールを導入するのに役立つフレームワークです。**これは SDLC の一般的な説明であり、このフレームワークをプロジェクトのニーズに合わせて調整します。

#### フェーズとアーティファクトへの潜入

ここで、上に挙げた5つのフェーズを詳しく見て、主な目的、起こること、実行する人を明確にします。

* **開始** フェーズ：これはプロジェクトの最初のフェーズであり、フィールドから要件を収集してプロジェクトに対して定義します。機能(エンドユーザー向けに作成される機能など)とセキュリティ(エンドユーザーがソフトウェア製品を信頼できるように実装する必要があるセキュリティ機能など)の両方の要件が含まれている必要があります。このフェーズでは、技術的作業を開始する前に行う必要があるすべてのアクティビティとその他予想できるすべてのアクティビティが実行されます。これは概念実証を行うことやプロジェクトの実行可能性を確認する時期でもあります。通常、マーケティング(マーケティング担当者、プロダクトオーナー、など)、経営、財務などのビジネス機能に近いチームが関与します。
* **アーキテクチャおよび設計** フェーズ：プロジェクトが承認された後、技術チームはコーディングチームが生産性を高めるための初期の技術アクティビティに取り掛かります。この事項では、リスクを分析して、関連する対策を特定および明確にします。アーキテクチャ、コーディングアプローチ、テスト戦略、適切なツールが確認され、さまざまな環境(DEV, QA, SIT, UAT, PROD など)を作成および配置します。このフェーズは要求の技術的ではない定義から、技術チームがソフトウェア製品を構成するコードを生み出す準備が整う段階に移行することを主な目的としており、きわめて重要です。通常、アーキテクト、設計担当者、QAチーム、テスト担当者、アプリセキュリティ専門家が関与します。
* **コーディング** フェーズ：これはコードが作成されて成果が目に見える時期です。これは最も重要なフェーズとみなされます。しかし、現フェーズの前後で起きるすべてのアクティビティは、コード作成をサポートして、期限と予算を満たしながら品質とセキュリティが適切な基準に達することを確実にすることを念頭におく必要があります。このフェーズでは、開発チームは定義された環境で作業し、事前に定義されたガイドラインに従って要件を実装します。関与する主な人は開発者です。
* **テスト** フェーズ：これは作成されたソフトウェアをテストするフェーズです。テストにはさまざまな形があります(下記の SDLC でのセキュリティテストのセクションの説明を参照ください)ので、テストアクティビティはコーディング中に実施される可能性があります(明らかな目標はできるだけ早く問題を発見することです)。組織、プロジェクトリスクプロファイル、使用される技法によって、テストチームはコーディングチームから独立している場合があります。このフェーズで関与する主な人はテスト担当者です。確立されたセキュリティ要件に厳密にマップされ、理想的にはコード化およびその後の自動検証が可能な方法で提示されるテストケースが存在する必要があります。
* **リリース** フェーズ：この時点で、コードは作成およびテスト済みです。そのセキュリティレベルは評価済みです。多くの場合、コードが期待されるセキュリティレベルを満たすという証拠を裏付けるためにメトリクスが作成されます。しかし、現在、それは顧客に移行する必要があります。例えば、ステークホルダ(経営、マーケティング、など)は市場における価値を創造して顧客に経済的利益をもたらすことができるように受け入れなければなりません。それに続いて、それは市場で利用可能になります。セキュアなソフトウェアを作るだけでは不十分です。現在、(短期的にも長期的にも)セキュアであり続けながら、安全に生産環境に移行する必要があります。運用チームのドキュメントが作成されることがあります。このフェーズでは、ステークホルダ(経営、マーケティング、など)が最初に関与して、技術チーム(テスト、運用、品質保証、など)が同様に関与します。

前述の説明は「ウォータフォール系」であるように見えるかもしれませんが、アジャイル手法にも適用されます。同じロジックが使用されますが、より反復的な方法になります。一部のアクティビティ(プロジェクトの開始など)は一度だけ行われる可能性がありますが、(新しい要件を明示してユーザーストーリーを明確にするなど)プロジェクト全体で同様のアクティビティの一部が定期的に行われます。同じように、テストはプロジェクトの最後に一度だけではなく、各イテレーションでは、テストはそのイテレーションで作成されたコードに焦点を当てます。このインサイクルテストは、開発者がフィードバックを受け取るのに時間がかかり、コンテキストスイッチを作成するのにかかる時間が長くなるため、アウトオブサイクルアプローチよりも優先されます。

### SDLC でのセキュリティテスト

#### 概要

ソフトウェア開発(および他の多くの分野でも同じく)でよく知られていることとして、テストを早期に行うほど欠陥を修正することがより簡単でコスト効率に優れているということがあります。サイバーセキュリティに関する欠陥にも同じことが当てはまります。開発ライフサイクルの早い段階で脆弱性を特定(および修正)することで、セキュアなソフトウェアを生み出す際により良い結果が得られます。いくつかの点で、品質テストとセキュリティテストは両方とも顧客満足度を高めることを意味する共通の側面を共有する場合があります。

テストはライフサイクルの中で多くの形で実行されます。静的解析などの自動ツールを使用し、コードを作成した際にユニットテストを書き、ソフトウェアが開発された後にペネトレーションテストを(手動でもしくはスキャニングツールの助けを借りて)実行します。しかし、セキュア SDLC では早期にこれらの取り組みを計画および準備することを常に重視する必要があります。プロジェクトの開始時にテスト計画を開始および開発する必要があります。実行されるテストの種類、その範囲、実行方法と時期、予算をリストアップして明確にします。また、開発全般でテストチームにガイダンスを提供するために、悪用ケースは早期に(理想的にはユースケースが作成されると同時に)プロジェクトで記述する必要があります。最後に、常に考慮すべきアーティファクトは脅威モデリングであり、チームは適切なテストと適切なカバレッジを備えたアーキテクチャの適切なコンポーネントに焦点を当て、セキュリティコントロールが正しく実装されていることを確認します。

以下の図は SDLC でテストを実行する方法の概要を示しています。

-- TODO [Add diagram to summarize the above paragraph and clarify the way test should be performed (planned, executed and reviewed)] --

#### 詳細な説明

前述のように、SDLC に沿っていくつかの種類のテストを行います。対象となるソフトウェアのリスクプロファイルによって、いくつかの種類のテストを実行します。

* **解析**: 本質的に、静的解析は実行せずにソースコードを解析するものです。このアーティファクトの目的は2つあります。コードの作成時にチームが合意したセキュアコーディングルールで正しく実装されていることを確認すること、および脆弱性を見つけることです。通常、数百ないし数千行のコードを解析する必要があるため、専用のソフトウェアツールを使用してこのタスクを自動化します。但し、ツールは探し求めたものしか発見することができないという欠点があり、今日、人間ほど成功してはいません。これが静的解析が(ツール以外にも)人間によって実行されることがある理由です。人間はより時間を要するかもしれませんが、脆弱性を発見するための創造的な方法を持っています。静的解析のツールの例は別のセクションで記載されています。
* **単体テスト**: 単体テストはソースコードに最も近い(単一のユニットにフォーカスしているなど)一連のテストを構成し、コードと共に実行されます。使用している方法論によれば、コードを開発する前(テスト駆動開発(TDD)として知られています)もしくは直後に作成されます。どのような場合でも、最終目標は作成されたコードが期待通りに動作することを検証することだけでなく、悪用ケースを防御(入力フィルタリング/検証、ホワイトリスト、など)して、かつ回避できないように適切にコントロールが配置されていることも検証します。単体テストは開発ライフサイクルの早期に問題を検出することで、可能な限り迅速で効果的に修正することができます。これらのテストは統合/検証/妥当性確認テストなどの他のテストとは異なり、同じ種類の問題を検出するためには使用できません。通常、単体テストはツールで支援されます。そのうちのいくつかは別のセクションに記載されています。
* **ペネトレーションテスト**: これはセキュリティテストの「王様」であり、最も有名でよく実行されるものです。但し、開発ライフサイクルの後半に行われ、すべての欠陥を見つけられるわけではないことに注意する必要があります。それらは利用可能なリソース(時間、金銭、専門知識、など)によって制約を受けることが多いため、他の種類のテストで補完する必要があります。現在のガイドはペネトレーションテストについてのものであり、読者は多くの価値のあるテストを行いより多くの脆弱性を発見するために役に立つ情報を見つけるでしょう。ペネトレーションテスト技法には脆弱性スキャンとファジングがあります。しかし、ペネトレーションテストはこれら2つの例以外にも多面的です。役に立つツールは別のセクションに記載されています。

品質テストとセキュリティテストの間には明確な違いがあります。品質テストは明示的に計画された機能が適切な方法で実装されていることを確認しますが、セキュリティテストは以下について確認します。

* 既存の機能が悪意のある方法で使用できないこと
* システムやユーザーを危険にさらす可能性のある新機能が無意識のうちに導入されてはいないこと

結果として、ひとつのタイプのテストを実行するだけでは、作り出されるソフトウェアが利便性とセキュアの両方を兼ね備えることの両方のタイプをカバーするには十分ではありません。両方のタイプのテストは同様に重要であるため同じように注意を払う必要があります。最終的なユーザーは今日では品質(彼らが期待する方法で実行される実際の機能など)とセキュリティ(彼らの金銭が盗まれないことや私生活がプライベートのまま固持されることについてソフトウェアベンダーを信じられること)の両方を重視します。

#### テスト戦略の定義

テスト戦略の目的は SDLC 全体でどのテストがどのくらいの頻度で実行されるかを定義することです。目的は2つあります。顧客 / 法務 / マーケティング / コーポレートチームにより一般的に表現される、セキュリティ目標が最終的なソフトウェア製品によって達成されることを確認すること、および費用対効果をもたらすことです。テスト戦略は一般にプロジェクトの開始時に作成されます。リスクが明確にされた後(開始フェーズ)ですが、コード作成(コーディングフェーズ)を開始する前になります。一般的にはアーキテクチャおよび設計フェーズで行われます。リスク管理、脅威モデリング、セキュリティエンジニアリングなどのアクティビティから入力を受け取ります。

-- TODO [Add diagram (in the form of a workflow) showing inputs of a Test Strategy, and outputs (test cases, ...)] --

テスト戦略は必ずしも正式に書かれている必要はありません。(アジャイルプロジェクトでは)ストーリーを使用して記述されるかもしれませんし、チェックリストの形で手早く記述したり、テストケースが特定のツールで書かれることもあります。しかし、それは確実に共有される必要があります。アーキテクチャチームによって定義されるかもしれませんが、開発、テスト、品質保証などの他のチームによって実装される必要があります。さらに、すべての技術チームが承認する必要があります。いずれかのチームに容認できない負担をかけてはいけません。

理想的には、テスト戦略は以下のようなトピックに対処します。

* 達成すべき目標、およびコントロール下に置かれるリスクの記述。
* どのようにしてこれらの目標を達成してリスクを許容レベルにまで下げられるか、どのテストが必要か、誰がそれを実行するか、どのように、いつ、どのような頻度で行うか。
* 現在のプロジェクトの受け入れ基準。

その有効性と進捗状況に従うためには、メトリクスを定義して、プロジェクト全体で更新し、定期的にコミュニケーションする必要があります。基準全体が選択した関連するメトリクスで記述されます。最適なものはリスクプロファイル、プロジェクト、組織に依存していると言えます。しかし、以下のようなメトリクスの例があります。

* 実装されるセキュリティコントロールに関連するストーリーの数
* セキュリティコントロールと機密機能に関する単体テストのコードカバレッジ
* 各ビルド時に静的解析ツールによって検出されるセキュリティバグの数
* セキュリティバグのバックログの傾向(重要性によってソースされる可能性がある)

これらは単なる提案であり、あなたの場合には他のメトリクスがさらに重要となるかもしれません。メトリックはプロジェクトをコントロール下に置くための本当に強力なツールです。何が行っているかおよび目標に達成するために改善が必要なものは何かといったタイムリーな情報をプロジェクトマネージャが明確に把握できます。

### テスト手法

#### ブラックボックス

#### ホワイトボックス

#### グレーボックス

### チーム管理

-- TODO [Develop content on Team Management in SDLC] --

* explain the importance of Separation of Duties (developers VS testers, ...)
* internal VS sub-contracted pentests

### DevOps 環境でのセキュリティテスト

#### 概要

プロダクションへのデプロイメントの頻度が増え、DevOps ハイパフォーマーは1日に何度もプロダクションへデプロイするため、可能な限りセキュリティ検証タスクの多くを自動化することが基本です。これを容易にするベストアプローチはデプロイメントパイプラインにセキュリティを統合することです。デプロイメントパイプラインは継続的な統合と継続的なデリバリープラクティスの組み合わせであり、ラピッド開発を容易にしてすべてのコミット時にほぼ同時にフィードバックを受け取るために作成されます。デプロイメントパイプラインの詳細については以下のセクションで説明します。

#### デプロイメントパイプライン

組織または開発チームの成熟度によって、デプロイメントパイプラインは非常に洗練されたものになります。最も簡単な形式では、デプロイメントパイプラインはコミットフェーズで構成されます。コミットフェーズでは一般的に単純なコンパイラチェック、単体テストスイートが実行されるだけでなく、リリース候補と呼ばれるアプリケーションの展開可能なアーティファクトが作成されます。リリース候補はバージョン管理システムのトランクにチェックインされた最新バージョンの変更であり、デプロイメントパイプラインにより評価され、本番環境に展開される可能性のある確立された標準とインラインであるかどうかを検証します。

コミットフェーズは開発者に即時のフィードバックを提供するように設計されており、トランクのコミットごとに実行されます。そのため、一定の時間制約が存在します。通常、コミットフェーズは5分以内に実行する必要がありますが、いずれの場合も、完了までに10分以上かかることはありません。この時間制約は、現状の既存ツールの多くがそのような短時間で実行できないため、セキュリティコンテキストでは非常に困難です <sup>[14][15]</sup> 。

Todo: Automating security tools in Jenkins,...

## 改竄とリバースエンジニアリング

In the context of mobile apps, *reverse engineering* is the process of analyzing the compiled app to extract knowledge about its inner workings. It is akin to reconstructing the original source code from the bytecode or binary code, even though this doesn't need to happen literally. The main goal in reverse engineering is *comprehending* the code.

*Tampering* is the process of making changes to a mobile app (either the compiled app, or the running process) or its environment to affect its behavior. For example, an app might refuse to run on your rooted test device, making it impossible to run some of your tests. In cases like that, you'll want to alter that particular behavior.

Reverse engineering and tampering techniques have long belonged to the realm of crackers, modders, malware analysts, and other more exotic professions. For "traditional" security testers and researchers, reverse engineering has been more of a complementary, nice-to-have-type skill that wasn't all that useful in 99% of day-to-day work. But the tides are turning: Mobile app black-box testing increasingly requires testers to disassemble compiled apps, apply patches, and tamper with binary code or even live processes. The fact that many mobile apps implement defenses against unwelcome tampering doesn't make things easier for us.

Mobile security testers should be able to understand basic reverse engineering concepts. It goes without saying that they should also know mobile devices and operating systems inside out: the processor architecture, executable format, programming language intricacies, and so forth.

Reverse engineering is an art, and describing every available facet of it would fill a whole library. The sheer range of techniques and possible specializations is mind-blowing: One can spend years working on a very specific, isolated sub-problem, such as automating malware analysis or developing novel de-obfuscation methods. Security testers are generalists: To be effective reverse engineers, they must be able filter through the vast amount of information to build a workable methodology.

There is no generic reverse engineering process that always works. That said, we'll describe commonly used methods and tools later on, and give examples for tackling the most common defenses.

### 必要な理由

Mobile security testing requires at least basic reverse engineering skills for several reasons:

**1. To enable black-box testing of mobile apps.** Modern apps often employ technical controls that will hinder your ability to perform dynamic analysis. SSL pinning and end-to-end (E2E) encryption sometimes prevent you from intercepting or manipulating traffic with a proxy. Root detection could prevent the app from running on a rooted device, preventing you from using advanced testing tools. In this cases, you must be able to deactivate these defenses.

**2. To enhance static analysis in black-box security testing.** In a black-box test, static analysis of the app bytecode or binary code is helpful for getting a better understanding of what the app is doing. It also enables you to identify certain flaws, such as credentials hardcoded inside the app.

**3. To assess resiliency against reverse engineering.**  Apps that implement the software protection measures listed in MASVS-R should be resilient against reverse engineering to a certain degree. In this case, testing the reverse engineering defenses ("resiliency assessment") is part of the overall security test. In the resiliency assessment, the tester assumes the role of the reverse engineer and attempts to bypass the defenses.

In this guide, we'll cover basic tampering techniques such as patching and hooking, as well as common tools and processes for reverse engineering (and comprehending) mobile apps without access to the original source code. Reverse engineering is an immensely complex topic however - covering every possible aspect would easily fill several books. Links and pointers to useful resources are included in the "references" section at the end of each chapter.

### 始める前に

Before you dive into the world of mobile app reversing, we have some good news and some bad news to share. Let's start with the good news:

**Ultimately, the reverse engineer always wins.**

This is even more true in the mobile world, where the reverse engineer has a natural advantage: The way mobile apps are deployed and sandboxed is more restrictive by design, so it is simply not feasible to include the rootkit-like functionality often found in Windows software (e.g. DRM systems). At least on Android, you have a much higher degree of control over the mobile OS, giving you easy wins in many situations (assuming you know how to use that power). On iOS, you get less control - but defensive options are even more limited.

The bad news is that dealing with multi-threaded anti-debugging controls, cryptographic white-boxes, stealthy anti-tampering features and highly complex control flow transformations is not for the faint-hearted. The most effective software protection schemes are highly proprietary and won't be beaten using standard tweaks and tricks. Defeating them requires tedious manual analysis, coding, frustration, and - depending on your personality - sleepless nights and strained relationships.

It's easy to get overwhelmed by the sheer scope of it in the beginning. The best way to get started is to set up some basic tools (see the respective sections in the Android and iOS reversing chapters) and starting doing simple reversing tasks and crackmes. As you go, you'll need to learn about the assembler/bytecode language, the operating system in question, obfuscations you encounter, and so on. Start with simple tasks and gradually level up to more difficult ones.

In the following section we'll give a high level overview of the techniques most commonly used in mobile app security testing. In later chapters, we'll drill down into OS-specific details for both Android and iOS.

### 基本的な改竄技法

#### バイナリパッチ適用

*Patching* means making changes to the compiled app - e.g. changing code in binary executable file(s), modifying Java bytecode, or tampering with resources. The same process is known as *modding* in the mobile game hacking scene. Patches can be applied in any number of ways, from decompiling, editing and re-assembling an app, to editing binary files in a hex editor - anything goes (this rule applies to all of reverse engineering). We'll give some detailed examples for useful patches in later chapters.

One thing to keep in mind is that modern mobile OSes strictly enforce code signing, so running modified apps is not as straightforward as it used to be in traditional Desktop environments. Yep, security experts had a much easier life in the 90s! Fortunately, this is not all that difficult to do if you work on your own device - it simply means that you need to re-sign the app, or disable the default code signature verification facilities to run modified code.

#### Code Injection

Code injection is a very powerful technique that allows you to explore and modify processes during runtime. The injection process can be implemented in various ways, but you'll get by without knowing all the details thanks to freely available, well-documented tools that automate it. These tools give you direct access to process memory and important structures such as live objects instantiated by the app, and come with many useful utility functions for resolving loaded libraries, hooking methods and native functions, and more. Tampering with process memory is more difficult to detect than patching files, making in the preferred method in the majority of cases.

Substrate, Frida and XPosed are the most widely used hooking and code injection frameworks in the mobile world. The three frameworks differ in design philosophy and implementation details: Substrate and Xposed focus on code injection and/or hooking, while Frida aims to be a full-blown "dynamic instrumentation framework" that incorporates both code injection and language bindings, as well as an injectable JavaScript VM and console.

However, you can also instrument apps with Substrate by using it to inject Cycript, the programming environment (a.k.a. "Cycript-to-JavaScript" compiler) authored by Saurik of Cydia fame. To complicate things even more, Frida's authors also created a fork of Cycript named "frida-cycript" that replaces Cycript's runtime with a Frida-based runtime called Mjølner<sup>[17]</sup>. This enables Cycript to run on all the platforms and architectures maintained by frida-core (if you are confused now don't worry, it's perfectly OK to be).

The release was accompanied by a blog post by Frida's developer Ole titled "Cycript on Steroids", which did not go that down that well with Saurik<sup>[18]</sup>.

We'll include some examples for all three frameworks. As your first pick, we recommend starting with Frida, as it is the most versatile of the three (for this reason we'll also include more Frida details and examples). Notably, Frida can inject a Javascript VM into a process on both Android and iOS, while Cycript injection with Substrate only works on iOS. Ultimately however, you can of course achieve many of the same end goals with either framework.

### 静的および動的バイナリ解析

Reverse engineering is the process of reconstructing the semantics of the original source code from a compiled program. In other words, you take the program apart, run it, simulate parts of it, and do other unspeakable things to it, in order to understand what it is doing and how.

#### 逆アセンブラおよび逆コンパイラの使用

Disassemblers and decompilers allow you to translate an app binary code or byte-code back into a more or less understandable format. In the case of native binaries, you'll usually obtain assembler code matching the architecture which the app was compiled for. Android Java apps can be disassembled to Smali, which is an assembler language for the dex format used by dalvik, Android's Java VM. The Smali assembly is also quite easily decompiled back to Java code.

A wide range of tools and frameworks is available: from expensive but convenient GUI tools, to open source disassembling engines and reverse engineering frameworks. Advanced usage instructions for any of these tools often easily fill a book on their own. The best way to get started though is simply picking a tool that fits your needs and budget and buying a well-reviewed user guide along with it. We'll list some of the most popular tools in the OS-specific "Reverse Engineering and Yampering" chapters.

#### Debugging and Tracing

In the traditional sense, debugging is the process of identifying and isolating problems in a program as part of the software development lifecycle. The very same tools used for debugging are of great value to reverse engineers even when identifying bugs is not the primary goal. Debuggers enable suspending a program at any point during runtime, inspect the internal state of the process, and even modify the content of registers and memory. These abilities make it *much* easier to figure out what a program is actually doing.

When talking about debugging, we usually mean interactive debugging sessions in which a debugger is attached to the running process. In contrast, *tracing* refers to passive logging of information about the app's execution, such as API calls. This can be done in a number of ways, including debugging APIs, function hooks, or Kernel tracing facilities. Again, we'll cover many of these techniques in the OS-specific "Reverse Engineering and Yampering" chapters.

### 高度な技法

For more complicated tasks, such as de-obfuscating heavily obfuscated binaries, you won't get far without automating certain parts of the analysis. For example, understanding and simplifying a complex control flow graph manually in the disassembler would take you years (and most likely drive you mad, way before you're done). Instead, you can augment your workflow with custom made scripts or tools. Fortunately, modern disassemblers come with scripting and extension APIs, and many useful extensions are available for popular ones. Additionally, open-source disassembling engines and binary analysis frameworks exist to make your life easier.

Like always in hacking, the anything-goes-rule applies: Simply use whatever brings you closer to your goal most efficiently. Every binary is different, and every reverse engineer has their own style. Often, the best way to get to the goal is to combine different approaches, such as emulator-based tracing and symbolic execution, to fit the task at hand. To get started, pick a good disassembler and/or reverse engineering framework and start using them to get comfortable with their particular features and extension APIs. Ultimately, the best way to get better is getting hands-on experience.

#### 動的バイナリ計装

Another useful method for dealing with native binaries is dynamic binary instrumentations (DBI). Instrumentation frameworks such as Valgrind and PIN support fine-grained instruction-level tracing of single processes. This is achieved by inserting dynamically generated code at runtime. Valgrind compiles fine on Android, and pre-built binaries are available for download.

The Valgrind README contains specific compilation instructions for Android - http://valgrind.org/docs/manual/dist.readme-android.html

#### エミュレーションベースの動的解析

Running an app in the emulator gives you powerful ways to monitor and manipulate its environment. For some reverse engineering tasks, especially those that require low-level instruction tracing, emulation is the best (or only) choice. Unfortunately, this type of analysis is only viable for Android, as no emulator for iOS exists (the iOS simulator is not an emulator, and apps compiled for an iOS device don't run on it). We'll provide an overview of popular emulation-based analysis frameworks for Android in the "Tampering and Reverse Engineering on Android" chapter.

#### Custom Tooling using Reverse Engineering Frameworks

Even though most professional GUI-based disassemblers feature scripting facilities and extensibility, they sometimes simply not well-suited to solving a particular problem. Reverse engineering frameworks allow you perform and automate any kind of reversing task without the dependence for heavy-weight GUI, while also allowing for increased flexibility. Notably, most reversing frameworks are open source and/or available for free. Popular frameworks with support for mobile architectures include Radare2<sup>[4]</sup> and Angr <sup>[5]</sup>.

#### 事例：シンボリック/コンコリック実行を使用したプログラム解析

In the late 2000s, symbolic-execution based testing has gained popularity as a means of identifying security vulnerabilities. Symbolic "execution" actually refers to the process of representing possible paths through a program as formulas in first-order logic, whereby variables are represented by symbolic values, which are actually entire ranges of values. Satisfiability Modulo Theories (SMT) solvers are used to check satisfiability of those formulas and provide a solution, including concrete values for the variables needed to reach a certain point of execution on the path corresponding to the solved formula.

Typically, this approach is used in combination with other techniques such as dynamic execution (hence the name concolic stems from *conc*rete and symb*olic*), in order to tone down the path explosion problem specific to classical symbolic execution. This together with improved SMT solvers and current hardware speeds, allow concolic execution to explore paths in medium size software modules (i.e. in the order of 10s KLOC). However, it also comes in handy for supporting de-obfuscation tasks, such as simplifying control flow graphs. For example, Jonathan Salwan and Romain Thomas have shown how to reverse engineer VM-based software protections using Dynamic Symbolic Execution (i.e., using a mix of actual execution traces, simulation and symbolic execution)<sup>[6]</sup>.

In the Android section, you'll find a walkthrough for cracking a simple license check in an Android application using symbolic execution.

#### ドメイン固有の逆難読化攻撃

-- TODO [Describe de-obfucscation of virtual machines and whiteboxes] --

### 参考情報

* [1] OWASP Mobile Application Security Verification Standard - https://www.owasp.org/images/f/f2/OWASP_Mobile_AppSec_Verification_Standard_v0.9.2.pdf
* [2] The Importance of Manual Secure Code Review - https://www.mitre.org/capabilities/cybersecurity/overview/cybersecurity-blog/the-importance-of-manual-secure-code-review
* [3] OWASP Code Review Introduction - https://www.owasp.org/index.php/Code_Review_Introduction
* [4] Radare2 - https://github.com/radare/radare2
* [5] Angr - http://angr.io
* [6] https://triton.quarkslab.com/files/csaw2016-sos-rthomas-jsalwan.pdf
* [7] HP DevInspect - https://saas.hpe.com/en-us/software/agile-secure-code-development
* [8] Codiscope SecureAssist - https://codiscope.com/products/secureassist/
* [9] Crawling Code - https://www.owasp.org/index.php/Crawling_Code
* [10] Mobile internet usage surpasses desktop usage for the first time in history - http://bgr.com/2016/11/02/internet-usage-desktop-vs-mobile
* [12] Worldwide Smartphone OS Market Share - http://www.idc.com/promo/smartphone-market-share/os
* [13] Android Design Principles - https://developer.android.com/design/get-started/principles.html
* [14] Official (ISC)2 Guide to the CSSLP (ISC2 Press), Mano Paul - https://www.amazon.com/Official-Guide-CSSLP-Second-Press/dp/1466571276/
* [15] Software Security: Building Security In (Addison-Wesley Professional), Gary McGraw - https://www.amazon.com/Software-Security-Building-Gary-McGraw/dp/0321356705/
* [16] The evolution of DevOps: Gene Kim on getting to continuous delivery - https://techbeacon.com/evolution-devops-new-thinking-gene-kim
* [17] Cycript fork powered by Frida - https://github.com/nowsecure/frida-cycript
* [18] Cycript on steroids: Pumping up portability and performance with Frida - https://www.reddit.com/r/ReverseEngineering/comments/50uweq/cycript_on_steroids_pumping_up_portability_and/
