---
masvs_v1_id:
- MSTG-STORAGE-5
masvs_v2_id:
- MASVS-STORAGE-2
platform: ios
title: キーボードキャッシュ内の機密データの調査 (Finding Sensitive Data in the Keyboard Cache)
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
---

## 概要

## 静的解析

- ソースコードから以下と類似の実装を探します。

```objectivec
  textObject.autocorrectionType = UITextAutocorrectionTypeNo;
  textObject.secureTextEntry = YES;
```

- Xcode の `Interface Builder` で xib ファイルとストーリーボードファイルを開き、適切なオブジェクトの `Attributes Inspector` で `Secure Text Entry` と `Correction` の状態を検証します。

アプリケーションはテキストフィールドに入力された機密情報のキャッシュを防ぐ必要があります。目的とする UITextFields, UITextViews, UISearchBars で `textObject.autocorrectionType = UITextAutocorrectionTypeNo` ディレクティブを使用して、プログラムでキャッシュを無効にすることでキャッシュを防止できます。PIN やパスワードなど、マスクすべきデータに対しては、`textObject.secureTextEntry` を `YES` に設定します。

```objectivec
UITextField *textField = [ [ UITextField alloc ] initWithFrame: frame ];
textField.autocorrectionType = UITextAutocorrectionTypeNo;
```

## 動的解析

脱獄済み iPhone が利用可能な場合、以下の手順を実行します。

1. `Settings > General > Reset > Reset Keyboard Dictionary` に移動して、iOS デバイスのキーボードキャッシュをリセットします。
2. アプリケーションを使用し、ユーザーが機密データを入力できる機能を特定します。
3. [デバイスシェルのアクセス (Accessing the Device Shell)](../../../techniques/ios/MASTG-TECH-0052.md) によって以下のディレクトリとそのサブディレクトリ (8.0 より前の iOS バージョンでは異なるかもしれません) から拡張子 `.dat` のキーボードキャッシュファイルを取得します:
`/private/var/mobile/Library/Keyboard/`
4. ユーザー名、パスワード、電子メールアドレス、クレジットカード番号などの機密データを探します。キーボードキャッシュファイルから機密データを取得できた場合、アプリはこのテストに不合格となります。

```objectivec
UITextField *textField = [ [ UITextField alloc ] initWithFrame: frame ];
textField.autocorrectionType = UITextAutocorrectionTypeNo;
```

脱獄していない iPhone を使用しなければならない場合:

1. キーボードキャッシュをリセットします。
2. すべての機密データを入力します。
3. アプリを再度使用し、オートコレクトが以前入力した機密情報を提示するかどうかを確認します。
