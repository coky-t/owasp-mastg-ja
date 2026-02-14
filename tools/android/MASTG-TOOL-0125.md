---
title: Apkleaks
platform: android
source: https://github.com/dwisiswant0/apkleaks
hosts: [windows, linux, macOS]
---

Apkleaks は Android APK ファイルの静的解析用に設計されたオープンソースユーティリティで、API キー、URL、AWS S3 バケット、Firebase URL などの機密データを特定することに主眼を置いています。このツールは文字列解析のプロセスを自動化し、ハードコードされたシークレットや潜在的なセキュリティ脆弱性の検出を容易にします。

カスタム正規表現ルールをサポートしており、ユーザーは JSON 設定ファイル [regexes.json](https://github.com/dwisiswant0/apkleaks/blob/master/config/regexes.json) を通じて検索条件を追加指定できます。
