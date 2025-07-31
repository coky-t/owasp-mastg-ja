---
masvs_category: MASVS-CODE
platform: android
title: メモリ破損バグ (Memory Corruption Bugs)
---

Android アプリケーションはメモリ破損問題のほとんどが対処されている VM 上で実行されます。これはメモリ破損バグがないという意味ではありません。たとえば [CVE-2018-9522](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-9522 "CVE in StatsLogEventWrapper") では Parcels を使用したシリアル化の問題に関連しています。また、ネイティブコードでは、一般的なメモリ破損のセクションで説明したのと同じ問題が引き続き発生します。さらに、 [BlackHat で](https://www.blackhat.com/docs/us-15/materials/us-15-Drake-Stagefright-Scary-Code-In-The-Heart-Of-Android.pdf "Stagefright") 示された Stagefright 攻撃のように、サポートサービスにメモリバグが見られます。

メモリリークもよく問題となります。これはたとえば `Context` オブジェクトへの参照が `Activity` 以外のクラスに渡される場合や、 `Activity` クラスへの参照をヘルパークラスに渡す場合に発生することがあります。
