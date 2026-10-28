# juice-shop

OWASP Juice Shop (Node/Express/Angular): lines marked 'vuln-code-snippet vuln-line' are the known vulnerable lines of its coding challenges. Measures detection only; unmarked code is not labelled safe.

Commit `717f5efa88` (MIT), scanned 2026-10-28T23:36:03+00:00.

Verdict mode counts only findings that claim a vulnerability; review mode adds security hotspots.

## Verdict mode

**7 of 35 vulnerable challenges flagged (20%)**

| Category | Flagged | Challenges |
|---|---|---|
| Broken Access Control | 1 | 4 |
| Broken Anti Automation | 0 | 1 |
| Broken Authentication | 0 | 5 |
| Improper Input Validation | 0 | 2 |
| Injection | 1 | 8 |
| Miscellaneous | 0 | 2 |
| Observability Failures | 0 | 2 |
| Security through Obscurity | 0 | 1 |
| Sensitive Data Exposure | 1 | 4 |
| Unvalidated Redirects | 1 | 2 |
| Vulnerable Components | 0 | 1 |
| XSS | 3 | 3 |

| Challenge | Category | Flagged by |
|---|---|---|
| accessLogDisclosureChallenge | Observability Failures | missed |
| adminSectionChallenge | Broken Access Control | missed |
| changeProductChallenge | Broken Access Control | missed |
| chatbotGreedyInjectionChallenge | Injection | missed |
| chatbotPromptInjectionChallenge | Injection | missed |
| dbSchemaChallenge | Injection | missed |
| directoryListingChallenge | Sensitive Data Exposure | missed |
| exposedMetricsChallenge | Observability Failures | missed |
| forgedReviewChallenge | Broken Access Control | codewatch:codewatch.js.nosql-injection |
| iacLeakedKeyChallenge | Sensitive Data Exposure | detect-secrets:Private Key |
| localXssChallenge | XSS | codewatch:codewatch.js.angular-bypass-sanitizer |
| loginAdminChallenge | Injection | missed |
| loginBenderChallenge | Injection | missed |
| loginJimChallenge | Injection | missed |
| nftMintChallenge | Improper Input Validation | missed |
| nftUnlockChallenge | Sensitive Data Exposure | missed |
| noSqlReviewsChallenge | Injection | codewatch:codewatch.js.nosql-injection |
| redirectChallenge | Unvalidated Redirects | codewatch:codewatch.js.substring-url-allowlist |
| redirectCryptoCurrencyChallenge | Unvalidated Redirects | missed |
| registerAdminChallenge | Improper Input Validation | missed |
| resetPasswordBenderChallenge | Broken Authentication | missed |
| resetPasswordBjoernChallenge | Broken Authentication | missed |
| resetPasswordBjoernOwaspChallenge | Broken Authentication | missed |
| resetPasswordJimChallenge | Broken Authentication | missed |
| resetPasswordMortyChallenge | Broken Anti Automation | missed |
| resetPasswordUvoginChallenge | Sensitive Data Exposure | missed |
| restfulXssChallenge | XSS | codewatch:codewatch.js.angular-bypass-sanitizer |
| scoreBoardChallenge | Miscellaneous | missed |
| tokenSaleChallenge | Security through Obscurity | missed |
| unionSqlInjectionChallenge | Injection | missed |
| vulnerableDockerImageChallenge | Vulnerable Components | missed |
| weakPasswordChallenge | Broken Authentication | missed |
| web3SandboxChallenge | Broken Access Control | missed |
| web3WalletChallenge | Miscellaneous | missed |
| xssBonusChallenge | XSS | codewatch:codewatch.js.angular-bypass-sanitizer |

## Review mode

**15 of 35 vulnerable challenges flagged (43%)**

| Category | Flagged | Challenges |
|---|---|---|
| Broken Access Control | 1 | 4 |
| Broken Anti Automation | 0 | 1 |
| Broken Authentication | 0 | 5 |
| Improper Input Validation | 0 | 2 |
| Injection | 6 | 8 |
| Miscellaneous | 0 | 2 |
| Observability Failures | 2 | 2 |
| Security through Obscurity | 0 | 1 |
| Sensitive Data Exposure | 2 | 4 |
| Unvalidated Redirects | 1 | 2 |
| Vulnerable Components | 0 | 1 |
| XSS | 3 | 3 |

| Challenge | Category | Flagged by |
|---|---|---|
| accessLogDisclosureChallenge | Observability Failures | semgrep:javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing |
| adminSectionChallenge | Broken Access Control | missed |
| changeProductChallenge | Broken Access Control | missed |
| chatbotGreedyInjectionChallenge | Injection | missed |
| chatbotPromptInjectionChallenge | Injection | missed |
| dbSchemaChallenge | Injection | semgrep:javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection |
| directoryListingChallenge | Sensitive Data Exposure | semgrep:javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing |
| exposedMetricsChallenge | Observability Failures | codewatch:codewatch.js.unauthenticated-metrics |
| forgedReviewChallenge | Broken Access Control | codewatch:codewatch.js.nosql-injection |
| iacLeakedKeyChallenge | Sensitive Data Exposure | detect-secrets:Private Key |
| localXssChallenge | XSS | codewatch:codewatch.js.angular-bypass-sanitizer |
| loginAdminChallenge | Injection | semgrep:javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection |
| loginBenderChallenge | Injection | semgrep:javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection |
| loginJimChallenge | Injection | semgrep:javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection |
| nftMintChallenge | Improper Input Validation | missed |
| nftUnlockChallenge | Sensitive Data Exposure | missed |
| noSqlReviewsChallenge | Injection | codewatch:codewatch.js.nosql-injection |
| redirectChallenge | Unvalidated Redirects | codewatch:codewatch.js.substring-url-allowlist |
| redirectCryptoCurrencyChallenge | Unvalidated Redirects | missed |
| registerAdminChallenge | Improper Input Validation | missed |
| resetPasswordBenderChallenge | Broken Authentication | missed |
| resetPasswordBjoernChallenge | Broken Authentication | missed |
| resetPasswordBjoernOwaspChallenge | Broken Authentication | missed |
| resetPasswordJimChallenge | Broken Authentication | missed |
| resetPasswordMortyChallenge | Broken Anti Automation | missed |
| resetPasswordUvoginChallenge | Sensitive Data Exposure | missed |
| restfulXssChallenge | XSS | codewatch:codewatch.js.angular-bypass-sanitizer, eslint:security/detect-object-injection |
| scoreBoardChallenge | Miscellaneous | missed |
| tokenSaleChallenge | Security through Obscurity | missed |
| unionSqlInjectionChallenge | Injection | semgrep:javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection |
| vulnerableDockerImageChallenge | Vulnerable Components | missed |
| weakPasswordChallenge | Broken Authentication | missed |
| web3SandboxChallenge | Broken Access Control | missed |
| web3WalletChallenge | Miscellaneous | missed |
| xssBonusChallenge | XSS | codewatch:codewatch.js.angular-bypass-sanitizer |

