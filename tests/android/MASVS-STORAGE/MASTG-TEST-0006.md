---
masvs_v1_id:
- MSTG-STORAGE-5
masvs_v2_id:
- MASVS-STORAGE-2
platform: android
title: テキスト入力フィールドでキーボードキャッシュが無効かどうかの判定 (Determining Whether the Keyboard Cache Is Disabled for Text Input Fields)
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
status: deprecated
covered_by: [MASTG-TEST-0258]
deprecation_note: New version available in MASTG V2
---

## 概要

## 静的解析

アクティビティのレイアウト定義では、XML 属性を持つ `TextViews` を定義できます。XML 属性 `android:inputType` に値 `textNoSuggestions` を指定すると、入力フィールドを選択してもキーボードキャッシュは表示されません。ユーザーはすべて手入力しなければなりません。

```xml
   <EditText
        android:id="@+id/KeyBoardCache"
        android:inputType="textNoSuggestions" />
```

機密情報を取得するすべての入力フィールドのコードにはこの XML 属性を含めて [キーボード候補を無効にする](https://developer.android.com/reference/android/text/InputType.html#TYPE_TEXT_FLAG_NO_SUGGESTIONS "Disable keyboard suggestions") 必要があります。

あるいは、開発者は以下の定数を使用できます。

| XML `android:inputType` | コード `InputType` | API レベル |
| -- | --- | - |
| [`textPassword`](https://developer.android.com/reference/android/widget/TextView#attr_android:inputType:~:text=_SUGGESTIONS.-,textPassword,-81) | [`TYPE_TEXT_VARIATION_PASSWORD`](https://developer.android.com/reference/android/text/InputType#TYPE_TEXT_VARIATION_PASSWORD "Text password input type") | 3 |
| [`textVisiblePassword`](https://developer.android.com/reference/android/widget/TextView#attr_android:inputType:~:text=_URI.-,textVisiblePassword,-91) | [`TYPE_TEXT_VARIATION_VISIBLE_PASSWORD`](https://developer.android.com/reference/android/text/InputType#TYPE_TEXT_VARIATION_VISIBLE_PASSWORD "Text visible password input type") | 3 |
| [`numberPassword`](https://developer.android.com/reference/android/widget/TextView#attr_android:inputType:~:text=_DECIMAL.-,numberPassword,-12) | [`TYPE_NUMBER_VARIATION_PASSWORD`](https://developer.android.com/reference/android/text/InputType#TYPE_NUMBER_VARIATION_PASSWORD "A numeric password field") | 11 |
| [`textWebPassword`](https://developer.android.com/reference/android/widget/TextView#attr_android:inputType:~:text=_ADDRESS.-,textWebPassword,-e1) | [`TYPE_TEXT_VARIATION_WEB_PASSWORD`](https://developer.android.com/reference/android/text/InputType#TYPE_TEXT_VARIATION_WEB_PASSWORD "Text web password input type") | 11 |

アプリケーションコードをチェックして、入力タイプが上書きされていないことを検証します。たとえば、`findViewById(R.id.KeyBoardCache).setInputType(InputType.TYPE_CLASS_TEXT)` を実行すると、入力フィールド `KeyBoardCache` の入力タイプが `text` に設定され、キーボードキャッシュが再度有効になります。

最後に、Android マニフェストで最低限必要な SDK バージョン (`android:minSdkVersion`) をチェックします。これは使用される定数をサポートしていなければならないためです (たとえば、`textWebPassword` には Android SDK バージョン 11 が必要です)。そうでなければ、コンパイルされたアプリはキーボードキャッシュを可能にする、使用される入力タイプ定数を尊重しません。

### 動的解析

アプリを起動し、機密データを取得する入力フィールドをクリックします。文字列候補が出る場合、これらのフィールドでキーボードキャッシュが無効になっていません。
