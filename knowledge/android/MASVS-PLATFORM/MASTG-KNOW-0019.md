---
masvs_category: MASVS-PLATFORM
platform: android
title: ディープリンク (Deep Links)
---

_ディープリンク_ はユーザーをアプリ内の特定のコンテンツに直接誘導するスキームの URI です。アプリは、Android Manifest に _インテントフィルタ_ を追加し、受信したインテントからデータを抽出してユーザーを適切なアクティビティに誘導することで、[ディープリンクをセットアップ](https://developer.android.com/training/app-links/deep-linking) できます。

Android は二種類のディープリンクをサポートしています。

- **カスタム URL スキーム**: 任意のカスタム URL スキーム (例: `myapp://`) を使用するディープリンクです (OS による検証は行われません)。
- **Android アプリリンク** (Android 6.0 (API レベル 23) 以降):`http://` および `https://` スキームを使用し、`autoVerify` 属性 (OS による検証をトリガーします) を含むディープリンクです。

**ディープリンクの衝突:**

検証されていないディープリンクを使用すると、重大な問題を引き起こす可能性があります。ユーザーのデバイスにインストールされている他のアプリが同じインテントを宣言し、処理しようとする可能性があるためです。これは **ディープリンクの衝突** として知られています。任意のアプリケーションが他のアプリケーションに属するまったく同じディープリンクの制御を宣言できます。

Android の最新バージョンでは、いわゆる _曖昧性解消ダイアログ_ が表示され、ディープリンクを処理すべきアプリケーションを選択するようにユーザーに促します。ユーザーは正規のアプリケーションではなく悪意のあるものを選択するミスをする可能性があります。

<img src="../../../Document/Images/Chapters/0x05h/app-disambiguation.png" width="50%" />

**Android アプリリンク:**

ディープリンクの衝突問題を解決するため、Android 6.0 (API レベル 23) では [**Android アプリリンク**](https://developer.android.com/training/app-links) を導入しました。これは開発者が明示的に登録したウェブサイト URL に基づく [検証済みディープリンク](https://developer.android.com/training/app-links/verify-site-associations "Verify Android App Links") です。アプリリンクをクリックすると、インストール済みのアプリであればすぐにオープンします。

未検証のディープリンクとの主な違いは以下のとおりです。

- アプリリンクは `http://` および `https://` スキームのみを使用し、その他のカスタム URL スキームは許可されません。
- アプリリンクは [Digital Asset Links ファイル](https://developers.google.com/digital-asset-links/v1/getting-started "Digital Asset Link") を HTTPS 経由で提供するために、有効なドメインが必要です。
- アプリリンクはディープリンクの衝突が発生しないため、ユーザーが開いたときに曖昧性解消ダイアログを表示しません。
