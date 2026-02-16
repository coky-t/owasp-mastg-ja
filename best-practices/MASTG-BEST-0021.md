---
title: 適切なエラーおよび例外処理を確保する (Ensure Proper Error and Exception Handling)
alias: ensure-proper-error-and-exception-handling
id: MASTG-BEST-0021
platform: android
knowledge: [MASTG-KNOW-0010]
---

Android における安全な例外およびエラー処理とは、機密情報の漏洩を防ぎ、障害を適切に管理し、エラーがセキュリティを侵害しないことを確保することです。制御されたログ記録は開発者向けに確保しておきますが、ユーザーに表示するエラーメッセージは汎用的なものに留めるべきです。[OWASP DevGuide](https://devguide.owasp.org/en/04-design/02-web-app-checklist/10-handle-errors-exceptions/) では、エンドユーザーにない情報を開示しないこと、開発者に機密性の高いユーザーデータを開示しないこと、認証や認可を脆弱にしない安全な障害モードを確保することに重点を置いて、これらの原則を強化しています。

- **機密情報の漏洩を避ける**: ユーザーに表示されるエラーメッセージは汎用的なものにし、内部情報を明かさないようにすべきです。ログは機密データを削除するためにサニタイズされ、認可された担当者に制限される必要があります。公式の [ログ情報漏洩](https://developer.android.com/privacy-and-security/risks/log-info-disclosure) ガイダンスでは、本番環境のログに機密データやスタックトレースを含めないように警告し、サニタイゼーションと冗長性削除を推奨しています。
- **安全にフェイルする**: 例外はセキュリティコントロールを脆弱にしてはいけません。セキュリティチェックでの何かしらの不合格は、**拒否** の結果となり、より弱い想定や安全でないフォールバックを許容するのではなくアクションをブロックする必要があります。フェイルオープンパスは一般的な攻撃ベクトルであるため、セキュリティメカニズムは明示的に許可されるまでアクセスをデフォルトで拒否すべきです。
- **厳密に検証して、エラーで中止する**: 予期しない形式や値はエラーとして扱う必要があります。部分的に検証された状態で続行してはいけません。たとえば、ネットワーク呼び出しがトランスポート層で成功しても、アプリケーション層でのバリデーションに失敗した場合、処理を停止する必要があります。バリデーションが失敗した場合、バリデーションを成功させるためにデータのサニタイズを試みてはいけません。

詳細については以下のリソースを参照してください。

- ["OWASP - Fail Securely"](https://owasp.org/www-community/Fail_securely)
- ["OWASP - Improper Error Handling"](https://owasp.org/www-community/Improper_Error_Handling)
- ["CWE-636 - Not Failing Securely ('Failing Open')"](https://cwe.mitre.org/data/definitions/636.html)
