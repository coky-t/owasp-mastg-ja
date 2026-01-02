---
masvs_category: MASVS-PLATFORM
platform: android
title: 暗黙的インテント (Implicit Intents)
---

インテントは、別のアプリケーションコンポーネントにアクションを要求するために使用できる、メッセージングオブジェクトです。インテントはさまざまな方法でコンポーネント間の通信を容易にしますが、基本的なユースケースは三つあります。アクティビティの開始、サービスの開始、ブロードキャストの配信です。

[Android 開発者ドキュメント](https://developer.android.com/guide/components/intents-filters#Types) によると、Android は以下の二種類のインテントを提供しています。

- **明示的インテント** は、対象アプリのパッケージ名または完全修飾コンポーネントクラス名のいずれかを提供することで、インテントを満たすアプリケーションを指定します。一般的に、明示的インテントは、開始したいアクティビティまたはサービスのクラス名を分かっているため、アプリ内のコンポーネントを開始するために使用します。たとえば、ユーザーのアクションへのレスポンスとしてアプリ内で新しいアクティビティを開始したり、バックグラウンドでファイルをダウンロードするサービスを開始したいのかもしれません。

  ```java
  // Note the specification of a concrete component (DownloadActivity) that is started by the intent.
  Intent downloadIntent = new Intent(this, DownloadActivity.class);
  downloadIntent.setAction("android.intent.action.GET_CONTENT")
  startActivityForResult(downloadIntent);
  ```

- **暗黙的インテント** は特定のコンポーネントを指定するのではなく、別のアプリのコンポーネントが処理できる一般的なアクションを宣言します。たとえば、ユーザーに地図上の場所を示したい場合、暗黙的インテントを使用して、地図上の特定の場所を表示するよう別の対応アプリに依頼できます。もう一つの例には、ユーザーがアプリ内の電子メールアドレスをクリックした場合、呼び出し側のアプリは特定の電子メールアプリを指定せず、ユーザーに選択を委ねることがあります。

  ```java
  // Developers can also start an activity by just setting an action that is matched by the intended app.
  Intent downloadIntent = new Intent();
  downloadIntent.setAction("android.intent.action.GET_CONTENT")
  startActivityForResult(downloadIntent);
  ```

暗黙的インテントの使用は複数のセキュリティリスクにつながる可能性があります。たとえば、呼び出し側のアプリが適切な検証なしに暗黙的インテントの戻り値を処理した場合や、インテントが機密データを含む場合、それが誤って認可されていないサードパーティに漏洩する可能性があります。

上述の問題、具体的な攻撃シナリオ、推奨事項の詳細については、こちらの [ブログ投稿](https://blog.oversecured.com/Interception-of-Android-implicit-intents/ "Interception of Android implicit intents")、[こちらの記事](https://wiki.sei.cmu.edu/confluence/display/android/DRD03-J.+Do+not+broadcast+sensitive+information+using+an+implicit+intent "DRD03-J. Do not broadcast sensitive information using an implicit intent")、[CWE-927](https://cwe.mitre.org/data/definitions/927.html "CWE-927: Use of Implicit Intent for Sensitive Communication") を参照してください。
