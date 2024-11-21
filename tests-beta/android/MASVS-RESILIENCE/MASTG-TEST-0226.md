---
title: AndroidManifest で有効になっているデバッグフラグ (Debuggable Flag Enabled in the AndroidManifest)
platform: android
id: MASTG-TEST-0226
type: [static]
weakness: MASWE-0067
---

## 概要

このテストケースでは、アプリの `AndroidManifest.xml` で `debuggable` フラグ ([`android:debuggable`](https://developer.android.com/guide/topics/manifest/application-element#debug)) が `true` に設定されているかどうかをチェックします。このフラグが有効になっていると、アプリをデバッグできるようになり、攻撃者がアプリの内部を検査したり、セキュリティコントロールをバイパスしたり、実行時の動作を操作できるようになります。

`debuggable` フラグを `true` に設定していても [直接的には脆弱性とはみなされません](https://developer.android.com/privacy-and-security/risks/android-debuggable) が、特に本番環境では、アプリのデータやリソースへの認可されていないアクセスを提供することになり、攻撃対象領域を著しく拡大します。

## 手順

1. [AndroidManifest から情報の取得 (Obtaining Information from the AndroidManifest)](../../../techniques/android/MASTG-TECH-0117.md) を使用して `AndroidManifest.xml` ファイルを取得します。
2. `debuggable` を検索します。
    - [Apktool](../../../tools/android/MASTG-TOOL-0011.md) などのツールを使用して素の XML を解析する場合は `android:debuggable` を探します。
    - [aapt2](../../../tools/android/MASTG-TOOL-0124.md) を使用する場合は `application-debuggable` を探します。

## 結果

出力には `debuggable` フラグが設定されているかどうか (`true` または `false`) を明示的に示す可能性があります。フラグが指定されていない場合、リリースビルドではデフォルトで `false` として扱われます。

## 評価

`debuggable` フラグが明示的に `true` に設定されている場合、そのテストケースは不合格です。これはアプリがデバッグを許可するように構成されていることを示しますが、本番環境には不適切です。

この問題を軽減するには、すべてのリリースビルドで AndroidManifest.xml の debuggable フラグが false に設定されていることを確認します。

**注:** `debuggable` フラグでデバッグを無効にすることは重要な第一歩ですが、高度な攻撃からアプリを完全に保護するわけではありません。熟練した攻撃者は、バイナリパッチ ([パッチ適用 (Patching)](../../../techniques/android/MASTG-TECH-0038.md) を参照) でデバッガをアタッチできるようにしたり、[Frida for Android](tools/android/MASTG-TOOL-0001.md) などのバイナリ計装ツールを使用して同様の機能を実現するなど、さまざまな方法でデバッグを有効にすることができます。より高いレベルのセキュリティを必要とするアプリでは、追加の防御層としてアンチデバッグ技法の実装を検討してください。詳細なガイダンスについては [デバッガ検出が実装されていない (Debugger Detection Not Implemented)](../../../weaknesses/MASVS-RESILIENCE/MASWE-0101.md) を参照してください。
