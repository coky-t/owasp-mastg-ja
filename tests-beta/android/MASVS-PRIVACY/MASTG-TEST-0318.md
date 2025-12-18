---
platform: android
title: 機密ユーザーデータを扱うことが知られている SDK API への参照 (References to SDK APIs Known to Handle Sensitive User Data)
id: MASTG-TEST-0318
type: [static]
weakness: MASWE-0112
profiles: [P]
---

## 概要

このテストはアプリが機密ユーザーデータ ([Google Play's Data safety section](https://support.google.com/googleplay/android-developer/answer/10787469?hl=en#types&zippy=%2Cdata-types) や関連するプライバシー規制で定義されているものなど) を扱うことが知られている SDK (サードパーティライブラリ) API を使用するかどうかを検証します。

前提条件として、ライブラリのドキュメントやコードベースをレビューして、データ収集のエントリポイントとして使用する SDK API メソッドを特定する必要があります。たとえば、[Google Analytics for Firebase](https://firebase.google.com/docs/analytics) の `FirebaseAnalytics` クラスは、ユーザーデータを収集するために使用できる [`setUserId`](https://firebase.google.com/docs/reference/android/com/google/firebase/analytics/FirebaseAnalytics#setUserId(java.lang.String)), [`setUserProperty`](https://firebase.google.com/docs/reference/android/com/google/firebase/analytics/FirebaseAnalytics#setUserProperty(java.lang.String,%20java.lang.String)), [`logEvent`](https://firebase.google.com/docs/reference/android/com/google/firebase/analytics/FirebaseAnalytics#logEvent(java.lang.String,%20android.os.Bundle)) などのメソッドを提供しています。

> 注: このテストは **潜在的な** 機密ユーザーデータの取り扱いのみを検出します。実際にユーザーデータが共有されていることを **確認** するには、[機密ユーザーデータを扱うことが知られている SDK API の実行時使用 (Runtime Use of SDK APIs Known to Handle Sensitive User Data)](MASTG-TEST-0319.md) を参照してください。

## 手順

1. [Android アプリのリバースエンジニアリング (Reverse Engineering Android Apps)](../../../techniques/android/MASTG-TECH-0013.md) を使用して、アプリをリバースエンジニアします。
2. [Android での静的解析 (Static Analysis on Android)](../../../techniques/android/MASTG-TECH-0014.md) を使用して、機密ユーザーデータが SDK に渡される可能性があるこれらのメソッドの使用を探します。

## 結果

出力には SDK メソッドが呼び出される場所をリストする可能性があります。

## 評価

アプリコードでこれらの SDK メソッドの使用を見つけることができた場合、そのテストケースは不合格です。これはアプリがサードパーティ SDK と機密ユーザーデータを共有していることを示します。そのような参照が見つからない場合、そのテストケースは合格です。
