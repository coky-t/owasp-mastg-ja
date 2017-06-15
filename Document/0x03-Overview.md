# OWASP モバイルセキュリティテストガイドの序文

OWASP モバイルセキュリティテストガイド (MSTG) は Android や iOS デバイスのセキュリティテストに特に焦点を当てた OWASP テストプロジェクトの拡張版です。

このプロジェクトの目標は Android や iOS デバイスでのアプリケーションのテストの対象、理由、時期、場所、方法を人々が理解できるようにすることです。このプロジェクトは OWASP Mobile Top 10, モバイルアプリセキュリティチェックリスト、モバイルアプリケーションセキュリティ検証標準 (MASVS) に対処するために設計された完全な一連のテストケースを提供します。

## Why Does the World Need a Mobile Application Security Testing Guide?

Every new technology introduces new security risks, and mobile computing is no different. Even though modern mobile operating systems like iOS and Android are arguably more secure by design compared to traditional Desktop operating systems, there's still a lot of things that can go wrong when security is not considered during the mobile app development process. Data storage, inter-app communication, proper usage of cryptographic APIs and secure network communication are only some of the aspects that require careful consideration.

Security concerns in the mobile app space differ from traditional desktop software in some important ways. Firstly, while not many people opt to carry a desktop tower around in their pocket, doing this with a mobile device is decidedly more common. As a consequence, mobile devices are more readily lost and stolen, so adversaries are more likely to get physical access to a device and access any of the data stored.

## モバイルアプリセキュリティの主要な領域

Many mobile app pen testers have a background in network and web app penetration testing, and a lot of their knowledge is useful in mobile app testing. Practically every mobile app talks to some kind of backend service, and those services are prone to the same kinds of attacks we all know and love. On the mobile app side however, there is only little attack surface for injection attacks and similar attacks. Here, the main focus shifts to data protection both on the device itself and on the network. The following are some of the key areas in mobile app security.

### ローカルデータストレージ

The protection of sensitive data, such as user credentials and private information, is a key focus in mobile security. Firstly, sensitive data can be unintentionally exposed to other apps running on the same device if operating system mechanisms like IPC are used improperly. Data may also unintentionally leak to cloud storage, backups, or the keyboard cache. Additionally, mobile devices can be lost or stolen more easily compared to other types of devices, so an adversary gaining physical access is a more likely scenario.

From the view of a mobile app, this extra care has to be taken when storing user data, such as using appropriate key storage APIs and taking advantage of hardware-backed security features when available. 

On Android in particular, one has to deal with the problem of fragmentation. Not every Android device offers hardware-backed secure storage. Additionally, a large percentage of devices run outdated versions of Android with older API versions. If those versions are to be supported, apps must restrict themselves to older API versions that may lack important security features. When the choice is between better security and locking out a good percentage of the potential user base, odds are in favor of better security. 

### 信頼できるエンドポイントとの通信

モバイルデバイスは一般的にさまざまなネットワークに接続します。それには他の (おそらく悪意のある) クライアントと共有される公衆 WiFi ネットワークもあります。これはネットワークベースの攻撃の大きな機会を生み出します。簡単なパケットスニッフィングから不正なアクセスポイントの作成や SSL 中間者攻撃 (またはルーティングプロトコルの注入など古いものであっても、悪いやつは気にしません) に至ります。

モバイルアプリとリモートサービスエンドポイントの間で交換される情報の機密性と完全性を維持することは重要です。最低限、モバイルアプリは適切な設定で TLS プロトコルを使用して、ネットワーク通信にセキュアで暗号化されたチャネルを設定する必要があります。

### 認証と認可

In most cases, user login to a remote service is an integral part of the overall mobile app architecture. Even though most of the the authentication and authentication and authorization logic happens at the endpoint, there are also some implementation challenges on the mobile app side. In contrast to web apps, mobile apps often store long-time session tokens that are are then unlocked via user-to-device authentication features such as fingerprint scan. While this allows for a better user experience (nobody likes to enter a complex password every time they start an app), it also introduces additional complexity and the concrete implementation has a lot of room for errors. 

Mobile app architectures also increasingly incorporate authorization frameworks such as OAuth2, delegating authentication to a separate service or outsourcing the authentication process to an authentication provider. Using OAuth2, even the client-side authentication logic can be "outsourced" to other apps on the same device (e.g. the system browser). Security testers must know the advantages and disadvantages of the different possible architectures.

### モバイルプラットフォームとの相互作用

The controls in this group ensure that the app uses platform APIs and standard components in a secure manner. Additionally, the controls cover communication between apps (IPC).

### コード品質とエクスプロイトの軽減

"Classical" injection and memory management issues play less of a role on the mobile app side. This is mostly due to the lack of the necessary attack surface: For the most part, mobile apps only interface with the trusted backend service and the UI, so even if a ton of buffer overflow vulnerabilities exist in the app, those vulnerabilities usually don't open up any useful attack vectors. The same can be said for browser exploits such as XSS that are very prevalent in the web world. Of course, there's always exceptions, and XSS is theoretically possible in some cases, but it's very rare to see XSS issues that one can actually exploit for benefit.

All this doesn't mean however that we should let developers get away with writing sloppy code. Following security best practice results in hardened release builds that are resilient against tampering. "Free" security features offered by compilers and mobile SDKs help to increase security and mitigate attacks.

### 改竄防止とリバース防止

There is three things you should never bring up in date conversations: Religion, politics and code obfuscation. Many security experts dismiss client-side protections outright. However, the fast is that software protection controls are widely used in the mobile app world, so security testers need ways to deal with them. We also think that there is *some* benefit to be had, as long as the protections are employed with a clear purpose and realistic expectations in mind, and aren't used to *replace* security controls.

## OWASP モバイルアプリセキュリティ検証標準、チェックリスト、テストガイド

このガイドは3つの密接に関連するモバイルアプリケーションセキュリティドキュメントのセットに属しています。3つのドキュメントはすべて同じセキュリティ要件の基本セットにマップします。状況に応じて、さまざまな目的を達成するために、単体で使用することも組み合わせて使用することもできます。

* **モバイルアプリケーションセキュリティ検証標準 (MASVS):** モバイルアプリのセキュリティモデルを定義し、モバイルアプリの一般的なセキュリティ要件を示す標準。これはアーキテクト、開発者、テスト担当者、セキュリティ専門家、消費者がセキュアなモバイルアプリケーションとは何であるかを定義するために使用できます。
* **モバイルセキュリティテストガイド (MSTG):** モバイルアプリのセキュリティをテストするためのマニュアル。オペレーティングシステム特有のベストプラクティス(現時点では Android および iOS 向け)とともに MASVS で定義されている要件の検証手順を提供します。MSTG はモバイルアプリのセキュリティテストの完全性と一貫性を保証します。また、モバイルアプリケーションセキュリティテスト担当者の単体の学習リソースやリファレンスガイドとしても役立ちます。
* **モバイルアプリセキュリティチェックリスト:** 実際の評価の中で MASVS に対するコンプライアンスを追跡するためのチェックリスト。このリストは各要件の MSTG テストケースに都合よくリンクしており、モバイルペネトレーションアプリテストを簡単に行うことができます。

![Document Overview](Images/Chapters/0x03/owasp-mobile-overview.jpg)

例えば、MASVS 要件は計画およびアーキテクチャ設計の段階で使用され、チェックリストやテストガイドは手動セキュリティテストのベースラインとして、もしくは開発後の自動セキュリティテストのテンプレートとして使用できます。次の章では、モバイルアプリケーションのペネトレーションテストの中でチェックリストやガイドを実際にどのように適用できるかについて説明します。

## モバイルセキュリティテストガイドの構成

MASVS で指定されているすべての要件はテストガイドに技術的な詳細を記述されています。MSTG の主要なセクションについてこの章で簡単に説明します。

このガイドは以下のように構成されています。

- テストプロセスと技法のセクションでは、モバイルアプリのセキュリティテスト手法、脆弱性解析技法、SDLC におけるセキュリティテスト、脆弱性解析技法を紹介します。

- Android テストガイドには、セキュリティ入門、セキュリティテストケース、リバースエンジニアリングと改竄の技法と対策など、Android プラットフォームに固有のすべてが含まれています。

- iOS テストガイドには、iOS オペレーティングシステムの概要、セキュリティテスト、リバースエンジニアリングとリバース防止など、iOS に固有のすべてが含まれています。

- 付録では、認証とセッション管理、ネットワーク通信、暗号化などのモバイル OS とは独立して適用される技術的なテストケースについて説明します。また、ソフトウェア保護スキームを評価するための方法論も含んでいます。
