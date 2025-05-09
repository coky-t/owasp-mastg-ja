---
title: 最新の minSdkVersion を使用する (Use Up-to-Date minSdkVersion)
alias: use-up-to-date-min-sdk-version
id: MASTG-BEST-0010
platform: android
---

`build.gradle` ファイル内の `minSdkVersion` が、ユーザーベースとの互換性を維持しながら、アプリの要件に適合する Android プラットフォームの最新バージョンに設定されていることを確保します。

企業はアプリをできるだけ多くのデバイスで利用できるようにしたいため、`minSdkVersion` を増やすことをためらうことがよくあります。Google は、[`targetSdkVersion` のようには](https://support.google.com/googleplay/android-developer/answer/11926878)、特定の `minSdkVersion` を強制しませんが、`minSdkVersion` を低く設定すると、**セキュリティに直接影響を及ぼし**、**ユーザーを脆弱性にさらし**、**アプリが重要なセキュリティ保護を活用できなくなる** ため、その影響を理解することが極めて重要です。

## 違いを明確にする: `targetSdkVersion` と `minSdkVersion`

- `targetSdkVersion`: アプリが動作するように _設計_ された最高 API レベルを定義します。アプリはより低い API レベルでも動作 _できます_ が、必ずしもすべての新しいセキュリティ強化を利用できるわけではありません。
- `minSdkVersion`: アプリが動作するように _許可_ された最低 API レベルを定義します。多くのセキュリティ機能は、特定の API レベル以上で動作するデバイスでのみ利用できるため、これは極めて重要です。`minSdkVersion` を低く設定すると、古いデバイスではアプリが **これらの保護機能を完全に利用できなくなります**。

`targetSdkVersion` を高く設定しても、アプリは最新のセキュリティ強化が **適用されていない** 古いデバイスでも動作します。`targetSdkVersion=33` (Android 13) だが `minSdkVersion=21` (Android 5) に設定すると、**何年にもわたる重要なセキュリティアップデートが適用されていない** Android  5 デバイスにもアプリをインストールできます。これらの古いデバイス上のマルウェアは、[Android Security Bulletins](https://source.android.com/docs/security/bulletin) に記載されている脆弱性からも明らかなように、アプリレベルのコードだけでは対処できないセキュリティ機能が不足しており、それを悪用する可能性があります。

`minSdkVersion` を増やすと、アプリを動作できるデバイスの数がわずかに減るかもしれませんが、**すべてのユーザーにベースラインレベルの保護** を確保するため、**セキュリティを大幅に強化します**。

## よくある誤解

Android 開発において `minSdkVersion` と `targetSdkVersion` には多くの誤解があります。Android ドキュメントでは「ターゲットとしている (targeting)」と記載されていますが、実際には「動作している (running on)」という意味です。たとえば、以下があります。

> [クリアテキストトラフィックをオプトアウトする](https://developer.android.com/privacy-and-security/security-config#CleartextTrafficPermitted): このセクションのガイダンスは、Android 8.1（API レベル 27）以下をターゲットとするアプリにのみ適用されます。Android 9（API レベル 28）以上では、クリアテキストのサポートがデフォルトで無効になっています。

注によると、このガイダンスは **API 27 以下をターゲットとする** アプリに適用されます。しかし実際には、**アプリが API 28 以上をターゲットとしているが、古い Android バージョン (API 28 未満) で動作している場合でも、** 明示的に無効にしない限り、**クリアテキストトラフィックは引き続き許可されます**。開発者は `targetSdkVersion` を増やすだけでクリアテキストを自動的にブロックすると考えるかもしれませんが、それは正しくありません。

## Android プラットフォームの注目すべき改善点の歴史

- Android 4.2 (API レベル 16) 2012年11月 (SELinux の導入)
- Android 4.3 (API レベル 18) 2013年7月 (SELinux がデフォルトで有効になる)
- Android 4.4 (API レベル 19) 2013年10月 (いくつかの新しい API と ART の導入された)
- Android 5.0 (API レベル 21) 2014年11月 (ART がデフォルトで使用され、その他多くの機能が追加された)
- Android 6.0 (API レベル 23) 2015年10月 (多くの新機能と改善点、インストール時の是非ではなく実行時のきめ細かい権限設定付与を含む)
- Android 7.0 (API レベル 24-25) 2016年8月 (ART 上の新しい JIT コンパイラ)
- Android 8.0 (API レベル 26-27) 2017年8月 (多くのセキュリティ改善点)
- Android 9 (API レベル 28) 2018年8月 (マイクやカメラのバックグラウンド使用の制限、ロックダウンモードの導入、すべてのアプリに対するデフォルト HTTPS)
- **Android 10 (API レベル 29)** 2019年9月 (「アプリ使用時のみ」位置情報へのアクセス、デバイス追跡防止、セキュア外部ストレージの改善)
    - [プライバシー (概要)](https://developer.android.com/about/versions/10/highlights#privacy_for_users "Android 10 Privacy Overview")
    - [プライバシー (詳細 1)](https://developer.android.com/about/versions/10/privacy "Android 10 Privacy Details 1")
    - [プライバシー (詳細 2)](https://developer.android.com/about/versions/10/privacy/changes "Android 10 Privacy Details 2")
    - [セキュリティ (概要)](https://developer.android.com/about/versions/10/highlights#security "Android 10 Security Overview")
    - [セキュリティ (詳細)](https://developer.android.com/about/versions/10/behavior-changes-all#security "Android 10 Security Details")
- **Android 11 (API レベル 30)** 2020年9月 (スコープ付きストレージの適用、パーミッション自動リセット、 [パッケージ可視性の抑制](https://developer.android.com/training/package-visibility) 、 APK 署名スキーム v4)
    - [プライバシー (概要)](https://developer.android.com/about/versions/11/privacy "Android 11 Privacy Overview")
    - [プライバシー動作の変更 (すべてのアプリ)](https://developer.android.com/about/versions/11/behavior-changes-all "Android 11 Privacy Behavior changes (all apps)")
    - [セキュリティ動作の変更 (すべてのアプリ)](https://developer.android.com/about/versions/11/behavior-changes-all#security "Android 11 Security Behavior changes (all apps)")
    - [プライバシー動作の変更 (バージョン 11 以上をターゲットとするアプリ)](https://developer.android.com/about/versions/11/behavior-changes-11#privacy "Android 11 Privacy Behavior changes (apps targeting version)")
    - [セキュリティ動作の変更 (バージョン 11 以上をターゲットとするアプリ)](https://developer.android.com/about/versions/11/behavior-changes-11#security "Android 11 Security Behavior changes (apps targeting version)")
- **Android 12 (API レベル 31-32)** 2021年8月 (Material You、ウェブインテントの解決、プライバシーダッシュボード)
    - [セキュリティとプライバシー](https://developer.android.com/about/versions/12/features#security-privacy)
    - [動作の変更 (すべてのアプリ)](https://developer.android.com/about/versions/12/behavior-changes-all#security-privacy)
    - [動作の変更 (バージョン 12 以上をターゲットとするアプリ)](https://developer.android.com/about/versions/12/behavior-changes-12#security-privacy)
- **Android 13 (API レベル 33)** 2022年 (コンテキスト登録されたレシーバーの安全なエクスポート、新しい写真ピッカー)
    - [セキュリティとプライバシー](https://developer.android.com/about/versions/13/features#privacy-security "Android 13 Security and privacy")
    - [プライバシー動作の変更 (すべてのアプリ)](https://developer.android.com/about/versions/13/behavior-changes-all#privacy "Android 13 Privacy Behavior changes (all apps)")
    - [セキュリティ動作の変更 (すべてのアプリ)](https://developer.android.com/about/versions/13/behavior-changes-all#security "Android 13 Security Behavior changes (all apps)")
    - [プライバシー動作の変更 (バージョン 13 以上をターゲットとするアプリ)](https://developer.android.com/about/versions/13/behavior-changes-13#privacy "Android 13 Privacy Behavior changes (apps targeting version)")
    - [セキュリティ動作の変更 (バージョン 13 以上をターゲットとするアプリ)](https://developer.android.com/about/versions/13/behavior-changes-13#security "Android 13 Security Behavior changes (apps targeting version)")
- **Android 14 (API レベル 34)** 2023年:
    - [変更の概要](https://developer.android.com/about/versions/14/summary "Android 14 Summary of changes")
    - [セキュリティ動作の変更 (すべてのアプリ)](https://developer.android.com/about/versions/14/behavior-changes-all#security "Android 14 Security Behavior changes (all apps)")
    - [セキュリティ動作の変更 (バージョン 14 以上をターゲットとするアプリ)](https://developer.android.com/about/versions/14/behavior-changes-14#security "Android 14 Security Behavior changes (apps targeting version)")
- **Android 15 (API レベル 35)** 2024年:
    - [変更の概要](https://developer.android.com/about/versions/15/summary "Android 15 Summary of changes")
    - [セキュリティ動作の変更 (すべてのアプリ)](https://developer.android.com/about/versions/15/behavior-changes-all#security "Android 15 Security Behavior changes (all apps)")
    - [セキュリティ動作の変更 (バージョン 15 以上をターゲットとするアプリ)](https://developer.android.com/about/versions/15/behavior-changes-15#security "Android 15 Security Behavior changes (apps targeting version)")
- **Android 16 (API レベル 36)** 2025年 (:material-flask: BETA):
    - [変更の概要](https://developer.android.com/about/versions/16/summary "Android 16 Summary of changes")
    - [セキュリティ動作の変更 (すべてのアプリ)](https://developer.android.com/about/versions/16/behavior-changes-all#security "Android 16 Security Behavior changes (all apps)")
    - [セキュリティ動作の変更 (バージョン 16 以上をターゲットとするアプリ)](https://developer.android.com/about/versions/16/behavior-changes-16#security "Android 16 Security Behavior changes (apps targeting version)")
