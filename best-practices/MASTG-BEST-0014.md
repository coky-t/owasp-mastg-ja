---
title: スクリーンショットと画面録画を防止する (Preventing Screenshots and Screen Recording)
alias: preventing-screenshots-and-screen-recording
id: MASTG-BEST-0014
platform: android
---

アプリが、スクリーンショット、画面録画、安全でないディスプレイ、タスクスイッチャのサムネイル、リモート画面共有から、カード番号やパスコードなど、機密コンテンツを隠していることを確認してください。マルウェアは画面出力をキャプチャし、機密情報を抽出する可能性があります。パスコードフィールドからキーストロークを漏洩する可能性があるため、スクリーンキーボードやカスタムキーパッドビューを保護してください。スクリーンショットは他のアプリやローカルの攻撃者がアクセスできる場所に保存される可能性があります。

ウィンドウに [`FLAG_SECURE`](https://developer.android.com/security/fraud-prevention/activities#flag_secure) を設定すると、スクリーンショットを防止 (または黒く表示) し、画面録画をブロックし、安全でないディスプレイとシステムタスクスイッチャのコンテンツを隠します。

<div style="display:flex; flex-wrap:wrap; gap:16px; align-items:flex-start; margin:16px 0;">
  <figure style="flex:1 1 220px; margin:0; text-align:center;">
    <img src="Images/Chapters/0x05d/task-switcher-without-flag-secure.png" width="200" alt="Task switcher without FLAG_SECURE">
    <figcaption>Without <code>FLAG_SECURE</code></figcaption>
  </figure>
  <figure style="flex:1 1 220px; margin:0; text-align:center;">
    <img src="Images/Chapters/0x05d/task-switcher-with-flag-secure.png" width="200" alt="Task switcher with FLAG_SECURE">
    <figcaption>With <code>FLAG_SECURE</code></figcaption>
  </figure>
</div>

アプリに `FLAG_SECURE` を実装するには公式のドキュメントに従って、["機密性の高いアクティビティを保護する"](https://developer.android.com/security/fraud-prevention/activities) を参照してください。
