---
masvs_category: MASVS-STORAGE
platform: ios
title: キーボードキャッシュ (Keyboard Cache)
---

キーボード入力を簡素化するために、オートコレクトやスペルチェックなどのいくつかのオプションがユーザーに利用可能であり、デフォルトでは `/private/var/mobile/Library/Keyboard/` およびそのサブディレクトリの `.dat` ファイルにキャッシュされます。

[`UITextInputTraits` プロトコル](https://developer.apple.com/reference/uikit/uitextinputtraits "UITextInputTraits protocol") はキーボードキャッシュに使用されます。`UITextField`, `UITextView`, `UISearchBar` クラスはこのプロトコルを自動的にサポートし、以下のプロパティを提供します。

- `var autocorrectionType: UITextAutocorrectionType` はタイピング時にオートコレクトを有効にするかどうかを決定します。オートコレクトが有効になっている場合、テキストオブジェクトは未知の単語を追跡し、適切な置換候補を提案します。ユーザーが置換を上書きしない限り、入力したテキストを自動的に置換します。このプロパティのデフォルト値は `UITextAutocorrectionTypeDefault` で、ほとんどの入力方式ではオートコレクトを有効にします。
- `var secureTextEntry: BOOL` は、テキストのコピーとテキストのキャッシュを無効にし、`UITextField` に入力されるテキストを隠すかどうかを決定します。このプロパティのデフォルト値は `NO` です。
