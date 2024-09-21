---
title: drozer
platform: android
source: https://github.com/WithSecureLabs/drozer
---

[drozer](https://github.com/WithSecureLabs/drozer "drozer on GitHub") は、Android 用のセキュリティテストフレームワークであり、Android ランタイム、他のアプリの IPC エンドポイント、基盤となる OS とやり取りするアプリの役割を仮定することによって、アプリやデバイスのセキュリティ脆弱性を検索できます。

drozer は Android のセキュリティ評価時に使用して、タスクを自動化できます。これによりテスト担当者やリバースエンジニアは以下のことが可能になります。

- Android アプリによって公開されている攻撃対象領域を発見して操作します。
- デバイス上で動的な Java コードを実行し、小さなテストスクリプトをコンパイルしてインストールする必要性を回避します。

drozer は Android エミュレータと実際のデバイスの両方で動作します。USB デバッグやその他の開発機能を有効にする必要がないため、実稼働状態のデバイスで評価を実行し、攻撃をシミュレートできます。

drozer を追加モジュールで拡張して、他の弱点を発見、テスト、悪用できます。これとスクリプトの可能性を組み合わせることで、セキュリティ問題の回帰テストを自動化するのに役立ちます。

## drozer のインストールとセットアップ

マシンに drozer コンソールをインストールおよびセットアップする方法と、Android フォンに drozer エージェントをインストールおよびセットアップする方法の詳細な手順は [drozer GitHub リポジトリ](https://github.com/WithSecureLabs/drozer "Installation instructions of drozer") にあります。

### 使用例

drozer をセットアップしたら、drozer を使用して、デバイス上の悪意のあるアプリの視点から Android アプリケーションの偵察と悪用を実行できます。[drozer ユーザーマニュアル](https://labs.withsecure.com/tools/drozer#3 "drozer User Manual") では、意図的に脆弱なアプリケーションである [sieve](https://github.com/WithSecureLabs/sieve "GitHub repo - sieve") を、ステップバイステップの悪用手順とともに紹介しています。

一般的な drozer コマンドには以下のようなものがあります。

#### デバイス上のアプリケーションの検索

```sh
run app.package.list -f <keyword>
```

これはバンドル識別子に "<keyword>" という単語を含むパッケージに関する基本情報をリストします。これには、パッケージ名、アプリケーションによって使用される主要なディレクトリ、アプリケーションによって使用または定義されるパーミッションを含みます。

#### アプリの攻撃対象領域の列挙

```sh
run app.package.attacksurface <package>
```

このコマンドはターゲットアプリのマニフェストを検査し、アプリケーションのエクスポートされたコンポーネントのレポートを提供し、アプリケーションがデバッグ可能かどうかを検証します。

攻撃対象領域を特定すると、各コンポーネントクラスに関するより具体的な情報を取得できます。たとえば、アクティビティをリストするには、以下のコマンドを使用します。

```sh
run app.activity.info -a <package>
```

これは、エクスポートされたすべてのアクティビティの名前と、それらとやり取りするために必要なパーミッションをリストします。

#### アクティビティの開始

エクスポートされたアクティビティを起動するには、以下のコマンドを使用します。

```sh
run app.activity.start --component <package> <component name>
```

`app.activity.start` を呼び出すと、より複雑なインテントを構築できます。他の drozer モジュールと同様に、`help` コマンドを使用することで、より詳しい使用情報を要求できます。

```sh
dz> help app.activity.start
Attempting to run shell module
usage: run app.activity.start [-h] [--action ACTION] [--category CATEGORY [CATEGORY ...]] [--component PACKAGE COMPONENT] [--data-uri DATA_URI] [--extra TYPE KEY VALUE] [--flags FLAGS [FLAGS ...]] [--mimetype MIMETYPE]
```

インテントの作成方法について詳しくは `help intents` を実行してください。

## 他の drozer リソース

役に立つ情報が見つかるかもしれないその他のリソースは以下のとおりです。

- [公式 drozer ユーザーマニュアル](https://labs.withsecure.com/tools/drozer "drozer User Manual")
- [drozer GitHub ページ](https://github.com/WithSecureLabs/drozer "GitHub repo - drozer")
- [drozer エージェント GitHub ページ](https://github.com/WithSecureLabs/drozer-agent "GitHub repo - drozer-agent")
