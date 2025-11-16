---
title: アプリサンドボックスディレクトリに暗号化したデータを保存する (Store Data Encrypted in App Sandbox Directory)
alias: store-data-encrypted-in-the-app-sandbox-directory
id: MASTG-BEST-0024
platform: ios
---

アプリとユーザーのデータをアプリサンドボックスに保存するための適切な場所を選択します ([アプリサンドボックスディレクトリ (App Sandbox Directories)](../knowledge/ios/MASVS-STORAGE/MASTG-KNOW-0108.md))。ユーザーが生成したコンテンツを保存するには **Documents** ディレクトリを使用し、アプリの内部データには **Library** ディレクトリを使用します。

アプリは、`UIFileSharingEnabled` と `LSSupportsOpeningDocumentsInPlace` を設定することで、ファイルアプリ内でユーザーが **Documents** ディレクトリにアクセスできるように設定できます。したがって、データベース、設定ファイル、購入状態をこのディレクトリに保存することは、以下の理由から非常に危険です。

- ユーザーはアプリ内部ファイルを改竄できます
- デバイスに物理的にアクセスできる攻撃者は `Documents` ディレクトリのコンテンツをコピーできます
- 他のアプリは [document picker interface](https://developer.apple.com/documentation/uikit/uidocumentpickerviewcontroller) で他のアプリの `Documents` ディレクトリにアクセスできます

**注:** データを正しいディレクトリに保存しても安全であるとは限りません。L2 プロファイルアプリでは、保存前にファイルを暗号化し、暗号鍵をキーチェーンに置くことをお勧めします。
