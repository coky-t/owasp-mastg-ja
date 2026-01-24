---
masvs_category: MASVS-PLATFORM
platform: ios
title: ユニバーサルリンク (Universal Links)
---

ユニバーサルリンクは Android アプリリンク (別名デジタルアセットリンク) の iOS 同等品であり、ディープリンクに使用されます。ユニバーサルリンク (アプリのウェブサイトへのリンク) をタップすると、ユーザーは Safari を経由することなく、対応するインストール済みアプリにシームレスにリダイレクトされます。アプリがインストールされていない場合は、リンクは Safari で開きます。

ユニバーサルリンクは標準的なウェブリンク (HTTP/HTTPS) であり、元々はディープリンクにも使用されていたカスタム URL スキームと混同してはいけません。

たとえば、Telegram アプリはカスタム URL スキームとユニバーサルリンクの両方をサポートしています。

- `tg://resolve?domain=fridadotre` はカスタム URL スキームであり、`tg://` スキームを使用します。
- `https://telegram.me/fridadotre` はユニバーサルリンクであり、`https://` スキームを使用します。

どちらも同じアクションとなり、ユーザーは Telegram 内で指定されたチャット (この場合は "fridadotre") にリダイレクトされます。但し、[Apple 開発者ドキュメント](https://developer.apple.com/library/archive/documentation/General/Conceptual/AppSearch/UniversalLinks.html "Universal Links") によると、ユニバーサルリンクはカスタム URL スキームを使用する際には当てはまらない重要な利点がいくつかあり、ディープリンクを実装するための推奨される方法です。具体的には、ユニバーサルリンクは以下のとおりです。

- **一意**: カスタム URL スキームとは異なり、ユニバーサルリンクはアプリのウェブサイトへの標準の HTTP または HTTPS リンクを使用するため、他のアプリにより要求できません。ユニバーサルリンクは URL スキームハイジャッキング攻撃 (元のアプリの後にインストールされたアプリが同じスキームを宣言し、システムがすべての新しいリクエストを最後にインストールされたアプリに誘導する可能性がある) を _防ぐ_ 方法として導入されました。
- **安全**: ユーザーがアプリをインストールすると、iOS はウェブサーバーにアップロードされたファイル (Apple App Site Association, AASA) をダウンロードしてチェックし、ウェブサイトはアプリが代わりに URL を開くことを許可していることを確認します。URL の正当な所有者のみがこのファイルをアップロードできるため、ウェブサイトとアプリの関連付けは安全です。
- **柔軟**: ユニバーサルリンクはアプリがインストールされていない場合でも機能します。ウェブサイトへのリンクをタップすると、ユーザーの期待どおりに Safari でコンテンツを開きます。
- **単一**: 一つの URL がウェブサイトとアプリの両方に機能します。
- **プライベート**: 他のアプリは、アプリがインストールされているかどうかを知らなくても、アプリと通信できます。

ユニバーサルリンクの詳細については Carlos Holguera による投稿 ["Learning about Universal Links and Fuzzing URL Schemes on iOS with Frida"](https://grepharder.github.io/blog/0x03_learning_about_universal_links_and_fuzzing_url_schemes_on_ios_with_frida.html "Learning about Universal Links and Fuzzing URL Schemes on iOS with Frida") を参照してください。
