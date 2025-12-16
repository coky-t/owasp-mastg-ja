---
masvs_category: MASVS-STORAGE
platform: ios
title: CoreData
---

[`Core Data`](https://developer.apple.com/library/content/documentation/Cocoa/Conceptual/CoreData/nsfetchedresultscontroller.html#//apple_ref/doc/uid/TP40001075-CH8-SW1 "Core Data iOS") はアプリケーションのオブジェクトのモデル層を管理するためのフレームワークです。永続化を含む、オブジェクトライフサイクルやオブジェクトグラフ管理に関連する一般的なタスクに対して、汎用的かつ自動化されたソリューションを提供します。[Core Data は永続ストアとして SQLite を使用できます](https://cocoacasts.com/what-is-the-difference-between-core-data-and-sqlite/ "What Is the Difference Between Core Data and SQLite") が、フレームワーク自体はデータベースではありません。

CoreData はデフォルトではデータを暗号化しません。MITRE Corporation によるオープンソースの iOS セキュリティコントロールに焦点を当てた研究プロジェクト (iMAS) の一環として、CoreData に追加の暗号レイヤを追加できます。詳細については [GitHub リポジトリ](https://github.com/project-imas/encrypted-core-data "Encrypted Core Data SQLite Store") をご覧ください。
