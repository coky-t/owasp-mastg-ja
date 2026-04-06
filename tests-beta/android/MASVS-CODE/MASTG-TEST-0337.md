---
title: 信頼できないデータのオブジェクトデシリアライゼーションへの参照 (References to Object Deserialization of Untrusted Data)
platform: android
id: MASTG-TEST-0337
type: [static]
weakness: MASWE-0088
profiles: [L1, L2]
knowledge: [MASTG-KNOW-0021]
---

## 概要

Android アプリは、`Intent` エクストラ、`Bundle` 値、IPC ペイロード、ネットワークレスポンスなど、プラットフォームのメカニズムを通じて受信したシリアライズされたデータからオブジェクトを再構築できます。アプリが、許可されるクラスを制限したり、使用前に入力を検証したりせずに、これらのソースからデータをデシリアライズすると、デシリアライゼーションロジックは意図しないアプリケーションの動作や安全でない状態変化をもたらす可能性があります。

このテストは、アプリが Android 上でオブジェクトデシリアライゼーションを使用しているかどうか、およびデシリアライズされたデータが適切なフィルタリングやバリデーションなしで信頼できない可能性のあるソースに由来しているかどうかをチェックします。Android のシリアライゼーションおよびデシリアライゼーションメカニズムの背景については、[オブジェクトシリアライゼーション (Object Serialization)](../../../knowledge/android/MASVS-PLATFORM/MASTG-KNOW-0021.md) を参照してください。

## 手順

1. アプリをリバースエンジニアします ([Android アプリのリバースエンジニアリング (Reverse Engineering Android Apps)](../../../techniques/android/MASTG-TECH-0013.md))。
2. 静的解析 ([Android での静的解析 (Static Analysis on Android)](../../../techniques/android/MASTG-TECH-0014.md)) を実行して、オブジェクトデシリアライゼーション API を探します。

## 結果

出力にはオブジェクトデシリアライゼーションが使用されている場所のリストを含む可能性があります。

## 評価

アプリが信頼できないソース (他のアプリケーションからのインテントエクストラなど) から受信したデータを適切なバリデーションや型フィルタリングなしでデシリアライズする場合、そのテストケースは不合格です。
