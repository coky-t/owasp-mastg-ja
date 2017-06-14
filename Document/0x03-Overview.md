# OWASP モバイルセキュリティテストガイドの序文

OWASP モバイルセキュリティテストガイド (MSTG) は Android や iOS デバイスのセキュリティテストに特に焦点を当てた OWASP テストプロジェクトの拡張版です。

このプロジェクトの目標は Android や iOS デバイスでのアプリケーションのテストの対象、理由、時期、場所、方法を人々が理解できるようにすることです。このプロジェクトは OWASP Mobile Top 10, モバイルアプリセキュリティチェックリスト、モバイルアプリケーションセキュリティ検証標準 (MASVS) に対処するために設計された完全な一連のテストケースを提供します。

## Why Does the World Need a Mobile Application Security Testing Guide?

Every new technology introduces new security risks, and mobile computing is no different. Even though modern mobile operating systems like iOS and Android are arguably more secure by design compared to traditional Desktop operating systems, there's still a lot of things that can go wrong when security is not considered during the mobile app development process. Data storage, inter-app communication, proper usage of cryptographic APIs and secure network communication are only some of the aspects that require careful consideration.

Security concerns in the mobile app space differ from traditional desktop software in some important ways. Firstly, while not many people opt to carry a desktop tower around in their pocket, doing this with a mobile device is decidedly more common. As a consequence, mobile devices are more readily lost and stolen, so adversaries are more likely to get physical access to a device and access any of the data stored. Also leaving a device unattended, which allows adversaries temporary physical access (Evil-Maid attack) can already lead to full compromise of the device or steal data without the owner noticing it.

## モバイルアプリセキュリティの主要な領域

Many mobile app pentesters have a background in network and web app penetration testing, and a lot of their knowledge is useful in mobile app testing. Practically every mobile app talks to some kind of backend service, and those services are prone to the same kinds of attacks we all know and love. On the mobile app side however, there is only little attack surface for injection attacks and similar attacks. Here, the main focus shifts to data protection both on the device itself and on the network. The following are some of the key areas in mobile app security.

### ローカルデータストレージ

モバイルアプリの観点から、ユーザーデータを格納する際には、適切なキーストレージ API を使用したり、利用可能であればハードウェア支援のセキュリティ機能を使用するなど、特別な注意が必要です。しかしここで別の問題が発生します。多くはアプリが実行されているデバイスやオペレーティングシステム、およびその設定に依存します。キーチェーンはパスコードでロックされていますか。一部の Android デバイスの場合のように、デバイスがハードウェア支援のセキュアストレージを提供しない場合はどうなりますか。アプリはこれを確認することができますか、そしてすべきですか、それともそれはユーザーの責任でしょうか。

モバイルデバイスに格納されるデータもデスクトップやラップトップに格納されるデータとは異なります。いずれも個人情報へのアクセスに使用されますが、これらの情報のコピーをモバイルデバイスで見つける可能性は非常に高くなります。さらに、さまざまな接続オプションとそれらの携帯性により、モバイルデバイスは電子ドアロックの鍵や支払カードの代替などとして使用されます。

ユーザーの資格情報や個人情報などの機密データを保護することはモバイルセキュリティの重要な焦点です。まず、IPC などのオペレーティングシステムのメカニズムが不適切に使用されている場合、機密データは同じデバイス上で動作している他のアプリに意図せずさらされている可能性があります。た、データはクラウドストレージ、バックアップ、キーボードキャッシュに意図せずリークすることもあります。さらに、モバイルデバイスは他の種類のデバイスに比べて紛失や盗難の可能性が高いため、攻撃者が物理的なアクセスを行うことはより可能性が高いシナリオとなります。

### 信頼できるエンドポイントとの通信

モバイルデバイスは一般的にさまざまなネットワークに接続します。それには他の (おそらく悪意のある) クライアントと共有される公衆 WiFi ネットワークもあります。これはネットワークベースの攻撃の大きな機会を生み出します。簡単なパケットスニッフィングから不正なアクセスポイントの作成や SSL 中間者攻撃 (またはルーティングプロトコルの注入など古いものであっても、動作している悪意のある行為の使用) に至ります。

モバイルアプリとリモートサービスエンドポイントの間で交換される情報の機密性と完全性を維持することは重要です。最低限、モバイルアプリは適切な設定で TLS プロトコルを使用して、ネットワーク通信にセキュアで暗号化されたチャネルを設定する必要があります。レベル 2 では SSL ピンニングなどの多層防御が追加されています。

### 認証とセッション管理

ほとんどの場合、リモートサービスへのユーザーログインはモバイルアプリのアーキテクチャ全体に不可欠な要素です。ほとんどのロジックはエンドポイントで発生しますが、MASVS ではユーザーアカウントとセッションの管理方法に関する基本的な要件をいくつか定義しています。要件はサービスエンドポイントのソースコードにアクセスすることなく簡単に検証できます。

### モバイルプラットフォームとの相互作用

-- [TODO] --

### コード品質とエクスプロイトの軽減

-- [TODO] --

### 改竄防止とリバース防止

-- [TODO] --

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
