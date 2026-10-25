---
masvs_category: MASVS-PLATFORM
platform: ios
title: アプリグループ (App Groups)
available_since: 8
---

アプリグループはエンタイトルメントに基づくメカニズムであり、同じ開発者チームによるアプリや拡張が、共通のファイルコンテナ、共有設定、SQLite データベースといったファイルを共有するものです。

## エンタイトルメント

アプリがアプリグループに参加するには、[App Groups 機能](https://developer.apple.com/documentation/xcode/configuring-app-groups) を有効にして [`com.apple.security.application-groups`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.application-groups) エンタイトルメントを追加します。App ID とプロビジョニングプロファイルには同一のグループ識別子を割り当てなければなりません。グループ識別子は `group.<reverse-DNS-string>` という形式であり、開発者チームに紐づけられます。

同じグループ識別子を共有するすべてのアプリと拡張は共有リソースにアクセスできます。異なる開発者チームが同じアプリグループを使用することはできません。

## 共有ストレージ

共有コンテナは [`containerURL(forSecurityApplicationGroupIdentifier:)`](https://developer.apple.com/documentation/foundation/filemanager/containerurl(forsecurityapplicationgroupidentifier:)) を介してアクセス可能なファイルシステム上のディレクトリです。

```swift
FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: "group.com.example.myapp")
```

アプリは一般的に以下を保存するためにこの場所を使用します。

- `UserDefaults(suiteName: "group.com.example.myapp")` を介した共有 `UserDefaults`。
- メインアプリと、ウィジェットや共有拡張といった拡張との間で共有される、SQLite データベース、Core Data ストア、その他のファイル。
- 共有の設定ファイルや構成データ。

## スコープと制約

- 共有コンテナは、同じデバイス上で実行し、そのグループに登録されているすべてのアプリと拡張にアクセス可能です。
- アプリグループは異なる開発者グループのアプリ間で共有することはできません。
- アプリグループは拡張の暗号化層を追加することはありません。共有コンテナ内のファイルは標準的な iOS ファイルシステム保護および各ファイルに適用されるデータ保護クラスに依存しています。
- ウィジェット、通知コンテンツ拡張、その他のアプリ拡張は一般的にアプリグループを使用して、それらを含むアプリで共有されるデータを読み取ります。
- グループ内の任意のアプリや拡張が共有データを読み取ったり変更できるため、機密データは最小限にすべきであり、アクセスはアプリケーション層で制御すべきです。

## 他のメカニズムとの関係

アプリ拡張 ([App Extension (App extensions)](MASTG-KNOW-0082.md) 参照) は、それを含むアプリとで主要なデータを共有するチャネルとして、一般的にアプリグループを使用します。複数のプロセスが共有コンテナ内の同じファイルを同時に読み書きする場合に、ファイル調整 ([ファイル調整 API (File Coordination APIs)](MASTG-KNOW-0127.md) 参照) が推奨されます。
