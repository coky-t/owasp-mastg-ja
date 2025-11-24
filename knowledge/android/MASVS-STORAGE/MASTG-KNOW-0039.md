---
masvs_category: MASVS-STORAGE
platform: android
title: Firebase リアルタイムデータベース (Firebase Real-time Databases)
---

Firebase は 15 を超えるプロダクトを備えた開発プラットフォームであり、その一つが Firebase リアルタイムデータベースです。アプリケーション開発者はこれを活用して、NoSQL クラウドホスト型データベースにデータを保存および同期できます。データは JSON で保存され、接続されたすべてのクライアントにリアルタイムで同期され、また、アプリケーションがオフラインになっても引き続き利用できます。

構成ミスのある Firebase インスタンスは以下のネットワーク呼び出しを行うことで識別できます。

`https://_firebaseProjectName_.firebaseio.com/.json`

_firebaseProjectName_ はアプリケーションをリバースエンジニアリングすることでモバイルアプリケーションから取得できます。あるいは、アナリストは [Firebase Scanner](https://github.com/shivsahni/FireBaseScanner "Firebase Scanner") を使用できます。これは以下で示すように上記のタスクを自動化する Python スクリプトです。

```bash
python FirebaseScanner.py -p <pathOfAPKFile>

python FirebaseScanner.py -f <commaSeparatedFirebaseProjectNames>
```
