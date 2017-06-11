# OWASP モバイルセキュリティテストガイドの序文

OWASP モバイルセキュリティテストガイド (MSTG) は Android や iOS デバイスのセキュリティテストに特に焦点を当てた OWASP テストプロジェクトの拡張版です。

このプロジェクトの目標は Android や iOS デバイスでのアプリケーションのテストの対象、理由、時期、場所、方法を人々が理解できるようにすることです。このプロジェクトは OWASP Mobile Top 10, モバイルアプリセキュリティチェックリスト、モバイルアプリケーションセキュリティ検証標準 (MASVS) に対処するために設計された完全な一連のテストケースを提供します。

## モバイルセキュリティテストの違い

技術革新は迅速に起こります。一昔前、スマートフォンは小さいキーボードを持つ魅力のない端末、技術に精通したビジネスユーザーのための高価な玩具でした。今日、スマートフォンは私たちの生活に不可欠なものです。私たちは情報、ナビゲーション、コミュニケーションのためにそれらに頼っています。ビジネスや社会生活の中の至るところにあります。

これらのデバイスで実行されているアプリは、私たちの個人情報、画像、音声、メモ、アカウントデータ、ビジネス情報、位置情報などを格納します。私たちが日常的に使用するサービスに接続するクライアントとして、そして他の人と交換するすべてのメッセージを処理する通信ハブとして動作します。他人のスマートフォンに侵入するとその人の人生にフィルタなしでアクセスできます。モバイルデバイスの紛失や盗難が増えモバイルマルウェアが増加していると考えられ、データ保護の必要性はよりいっそう明らかになっています。

すべての新しいテクノロジーは新しいセキュリティリスクをもたらします。モバイルコンピューティングも同様です。iOS や Android などの最新のモバイルオペレーティングシステムは従来のデスクトップオペレーティングシステムと比較して設計上セキュアであるにもかかわらず、モバイルアプリ開発プロセスでセキュリティが考慮されていない場合、うまくいかないことがまだ多くあります。データストレージ、アプリ間通信、暗号APIの適切な使い方や安全なネットワーク通信は慎重な検討が必要な局面のほんの一部です。

## モバイルアプリセキュリティの主要な領域

モバイルアプリ領域におけるセキュリティの問題は従来のデスクトップソフトウェアとはいくつかの重要な点で異なります。まず、デスクトップタワーをポケットに入れて持ち歩くことを望んでいる人はほとんどいませんが、モバイルデバイスでこれを行うことは明らかです。その結果として、モバイルデバイスの紛失や盗難が増え、攻撃者はデバイスに物理的にアクセスし格納されているデータにアクセスする可能性が高くなります。また、デバイスを放置すると、攻撃者は一時的に物理的にアクセスでき(悪意あるメイド攻撃)、所有者が気付かないうちにデバイスを完全に侵害したりデータを盗んだりすることができます。

### Local Data Storage

From the view of a mobile app, this extra care has to be taken when storing user data, such as using appropriate key storage APIs and taking advantage of hardware-backed security features when available. Here however we encounter another problem: Much depends on the device and operating system the app is running on, as well as its configuration. Is the keychain locked with a passcode? What if the device doesn't offer hardware-backed secure storage, as is the case with some Android devices? Can and should the app even verify this, or is it the responsibility of the user?

モバイルデバイスに格納されるデータもデスクトップやラップトップに格納されるデータとは異なります。いずれも個人情報へのアクセスに使用されますが、これらの情報のコピーをモバイルデバイスで見つける可能性は非常に高くなります。さらに、さまざまな接続オプションとそれらの携帯性により、モバイルデバイスは電子ドアロックの鍵や支払カードの代替などとして使用されます。

The protection of sensitive data, such as user credentials and private information, is a key focus in mobile security. Firstly, sensitive data can be unintentionally exposed to other apps running on the same device if operating system mechanisms like IPC are used improperly. Data may also unintentionally leak to cloud storage, backups, or the keyboard cache. Additionally, mobile devices can be lost or stolen more easily compared to other types of devices, so an adversary gaining physical access is a more likely scenario.

### Communication with Trusted Endpoints

Mobile devices regularly connect to a variety of networks, including public WiFi networks shared with other (possibly malicious) clients. This creates great opportunities for network-based attacks, from simple packet sniffing to creating a rogue access point and going SSL man-in-the-middle (or even old-school stuff like routing protocol injection - those baddies use whatever works).

It is crucial to maintain confidentiality and integrity of information exchanged between the mobile app and remote service endpoints. At the very least, a mobile app must set up a secure, encrypted channel for network communication using the TLS protocol with appropriate settings. Level 2 lists additional defense-in-depth measure such as SSL pinning.

### Authentication and Session Management

In most cases, user login to a remote service is an integral part of the overall mobile app architecture. Even though most of the logic happens at the endpoint, MASVS defines some basic requirements regarding how user accounts and sessions are managed. The requirements can be easily verified without access to the source code of the service endpoint.

### Interaction with the Mobile Platform

-- [TODO] --

### Code Quality and Exploit Mitigation

-- [TODO] --

### Anti-Tampering and Anti-Reversing

-- [TODO] --

## OWASP モバイルアプリセキュリティ検証標準、チェックリスト、テストガイド

このガイドは3つの密接に関連するモバイルアプリケーションセキュリティドキュメントのセットに属しています。3つのドキュメントはすべて同じセキュリティ要件の基本セットにマップします。状況に応じて、さまざまな目的を達成するために、単体で使用することも組み合わせて使用することもできます。

* **モバイルアプリケーションセキュリティ検証標準 (MASVS):** モバイルアプリのセキュリティモデルを定義し、モバイルアプリの一般的なセキュリティ要件を示す標準。これはアーキテクト、開発者、テスト担当者、セキュリティ専門家、消費者がセキュアなモバイルアプリケーションとは何であるかを定義するために使用できます。
* **モバイルセキュリティテストガイド (MSTG):** モバイルアプリのセキュリティをテストするためのマニュアル。オペレーティングシステム特有のベストプラクティス(現時点では Android および iOS 向け)とともに MASVS で定義されている要件の検証手順を提供します。MSTG はモバイルアプリのセキュリティテストの完全性と一貫性を保証します。また、モバイルアプリケーションセキュリティテスト担当者の単体の学習リソースやリファレンスガイドとしても役立ちます。
* **モバイルアプリセキュリティチェックリスト:** 実際の評価の中で MASVS に対するコンプライアンスを追跡するためのチェックリスト。このリストは各要件の MSTG テストケースに都合よくリンクしており、モバイルペネトレーションアプリテストを簡単に行うことができます。

![Document Overview](Images/Chapters/0x03/owasp-mobile-overview.jpg)

例えば、MASVS 要件は計画およびアーキテクチャ設計の段階で使用され、チェックリストやテストガイドは手動セキュリティテストのベースラインとして、もしくは開発後の自動セキュリティテストのテンプレートとして使用できます。次の章では、モバイルアプリケーションのペネトレーションテストの中でチェックリストやガイドを実際にどのように適用できるかについて説明します。

## Organization of the Mobile Security Testing Guide

All requirements specified in the MASVS are described in technical detail in the testing guide. The main sections of the MSTG are explained briefly in this chapter.

The guide is organized as follows: 

- In the Testing Processes and Techniques Section, we present the mobile app security testing methodology, vulnerability analysis techniques, security testing in the SDLC, and vulnerability analysis techniques. 

- The Android Testing Guide covers the everything specific to the Android platform, including security basics, security test cases, and reverse engineering and tampering techniques and preventions.

- The iOS Testing Guide Testing Guide covers everything specific to iOS, including an overview of the iOS OS, security testing, reverse engineering and anti-reversing.

- The appendix presents technical test cases that apply independent of mobile OS, such as authentication and session management endpoint, network communications, and cryptography. We also include a methodology for assessing software protection schemes.
