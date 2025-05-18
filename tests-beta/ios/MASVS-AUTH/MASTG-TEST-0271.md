---
platform: ios
title: 生体認証登録の変更を検出する API の実行時使用 (Runtime Use Of APIs Detecting Biometric Enrollment Changes)
id: MASTG-TEST-0271
apis: [kSecAccessControlBiometryCurrentSet,SecAccessControlCreateWithFlags]
type: [static]
weakness: MASWE-0046
status: draft
note: このテストは、攻撃者がシステム設定を介して新しい指紋や顔表現を追加することで生体認証をバイパスできるような方法で、アプリが Keychain API を使用しているかどうかを動的にチェックします。
---
