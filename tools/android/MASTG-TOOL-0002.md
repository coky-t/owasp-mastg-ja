---
title: MobSF for Android
platform: android
source: https://github.com/MobSF/Mobile-Security-Framework-MobSF
---

MobSF はその解析を終了すると、実行されたすべてのテストの一ページ概要を受け取ります。このページは複数のセクションに分かれており、アプリケーションの攻撃対象領域に関する最初のヒントを提供します。

<img src="../../Document/Images/Chapters/0x05b/mobsf_android.png" width="100%" />

以下が表示されます。

- アプリとそのバイナリファイルに関する基本情報。
- 以下のようないくつかのオプション:
    - `AndroidManifest.xml` ファイルを閲覧する。
    - アプリの IPC コンポーネントを閲覧する。
- 署名者証明書。
- アプリパーミッション。
- 既知の欠陥を示すセキュリティ解析 (アプリのバックアップが有効になっているかどうかなど)。
- アプリバイナリで使用されるライブラリのリストと、展開された APK 内のすべてのファイルのリスト。
- 悪意のある URL をチェックするマルウェア解析。

詳細については [MobSF ドキュメント](https://github.com/MobSF/Mobile-Security-Framework-MobSF/wiki/1.-Documentation "MobSF documentation") を参照してください。
