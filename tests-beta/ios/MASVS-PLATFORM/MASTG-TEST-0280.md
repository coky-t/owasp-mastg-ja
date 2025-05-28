---
platform: ios
title: ローカルデバイスに制限されていないペーストボードコンテンツ (Pasteboard Contents Not Restricted to Local Device)
id: MASTG-TEST-0280
type: [dynamic]
weakness: MASWE-0053
threat: [app]
status: draft
note: このテストはアプリが `UIPasteboard.OptionsKey.localOnly` オプションを指定した `UIPasteboard.setItems(_:options:)` メソッドを使用して、一般的なペーストボードのコンテンツをローカルデバイスに制限するかどうかをチェックします。
---
