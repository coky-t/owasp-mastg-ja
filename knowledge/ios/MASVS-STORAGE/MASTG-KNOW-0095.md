---
masvs_category: MASVS-STORAGE
platform: ios
title: Firebase リアルタイムデータベース (Firebase Real-time Databases)
---

Firebase は 15 を超えるプロダクトを備えた開発プラットフォームであり、その一つが Firebase リアルタイムデータベースです。それはアプリケーション開発者によって活用され、NoSQL クラウドホスト型データベースにデータを保存および同期できます。データは JSON として保存され、接続したすべてのクライアントにリアルタイムで同期されます。また、アプリケーションがオフラインになっても引き続き利用できます。

誤って構成した Firebase インスタンスは以下のネットワーク呼び出しを行うことで識別できます。

`https://\<firebaseProjectName\>.firebaseio.com/.json`

_firebaseProjectName_ はプロパティリスト (.plist) ファイルから取得できます。たとえば、_GoogleService-Info.plist_ ファイル内で `PROJECT_ID` キーは対応する Firebase プロジェクト名を保存します。

あるいは、アナリストは [Firebase Scanner](https://github.com/shivsahni/FireBaseScanner "Firebase Scanner") を使用することもできます。これは上記のタスクを以下に示すように自動化する Python スクリプトです。

```bash
python FirebaseScanner.py -f <commaSeparatedFirebaseProjectNames>
```
