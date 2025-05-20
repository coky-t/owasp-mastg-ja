---
masvs_v1_id:
- MSTG-CODE-5
masvs_v2_id:
- MASVS-CODE-3
platform: android
title: サードパーティーライブラリの脆弱性の確認 (Checking for Weaknesses in Third Party Libraries)
masvs_v1_levels:
- L1
- L2
status: deprecated
covered_by: [MASTG-TEST-0272, MASTG-TEST-0274]
deprecation_note: New version available in MASTG V2
---

## 概要

## 静的解析

サードパーティーに依存する脆弱性を検出するには OWASP Dependency checker を使用して実行できます。これは [`dependency-check-gradle`](https://github.com/jeremylong/dependency-check-gradle "dependency-check-gradle") などの gradle プラグインを使用することが最適です。
プラグインを使用するには、以下の手順を適用する必要があります。
build.gradle に以下のスクリプトを追加して、Maven セントラルリポジトリからプラグインをインストールします。

```default
buildscript {
    repositories {
        mavenCentral()
    }
    dependencies {
        classpath 'org.owasp:dependency-check-gradle:3.2.0'
    }
}

apply plugin: 'org.owasp.dependencycheck'
```

gradle がプラグインを呼び出したら、以下を実行してレポートを作成できます。

```bash
gradle assemble
gradle dependencyCheckAnalyze --info
```

特に設定しない限り、レポートは `build/reports` にあります。見つかった脆弱性を分析するにはレポートを使用します。ライブラリで見つかった脆弱性を考慮して対処方法を確認します。

プラグインは脆弱性フィードをダウンロードする必要があることに注意してください。プラグインで問題が発生した場合にはドキュメントを参照します。

最後に、ハイブリッドアプリケーションの場合には、RetireJS で JavaScript の依存関係を確認する必要があることに注意します。同様に Xamarin の場合には C# の依存関係を確認する必要があります。

ライブラリに脆弱性が含まれていることが判明した場合、以下の理由が適用されます。

- ライブラリがアプリケーションにパッケージされている場合、ライブラリに脆弱性が修正されたバージョンがあるかどうかを確認します。ない場合、脆弱性が実際にアプリケーションに影響するかどうかを確認します。その場合または将来そうなる可能性がある場合、同様の機能を提供するが脆弱性のない代替手段を探します。
- ライブラリがアプリケーションにパッケージされていない場合、脆弱性が修正されたパッチ適用バージョンがあるかどうかを確認します。そうでない場合には、ビルドプロセスに対する脆弱性の影響を確認します。脆弱性がビルドを妨げるかビルドパイプラインのセキュリティを弱める可能性がある場合、脆弱性が修正されている代替手段を探してみます。

ソースが利用できない場合、アプリを逆コンパイルして JAR ファイルを確認します。Dexguard や [ProGuard](../../../tools/android/MASTG-TOOL-0022.md) が適切に適用されている場合、ライブラリに関するバージョン情報は難読化されていることが多く、そのため失われています。そうでない場合には特定のライブラリの Java ファイルのコメントに非常に多くの情報を見つけることができます。MobSF などのツールはアプリケーションに同梱されている可能性のあるライブラリの解析に役立ちます。コメントや特定のバージョンで使用されている特定のメソッドを介して、ライブラリのバージョンを取得できる場合には、手動で CVE を検索します。

アプリケーションがリスクの高いアプリケーションである場合、ライブラリを手動で検査することになります。その場合、ネイティブコードに対する特定の要件があり、 "[コード品質のテスト](../../../Document/0x04h-Testing-Code-Quality.md)" の章にあります。その次に、ソフトウェアエンジニアリングのすべてのベストプラクティスが適用されているかどうかを調査するのが適切です。

## 動的解析

このセクションの動的解析はライセンスの著作権が遵守されているかどうかを検証することを含んでいます。これは多くの場合アプリケーションが `about` や `EULA` セクションを持つべきであることを意味しています。このセクションにはサードパーティライブラリのライセンスで必要とされる著作権に関する記述が記載されています。
