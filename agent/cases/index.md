# Case Index

> 由 `tool/build_case_index.py` 从结构化 case 确定性生成；`index.json` 是机器可读事实源。

- case 数量：9
- 内容指纹：`12000c2ca89b731efd59528ea2be9e7a4c62e107a89e56439b469bd3662899bf`

## Cases

| ID | 标题 | 场景 | 根因家族 | 信任边界 | Tactic | 文件 |
|---|---|---|---|---|---|---|
| CASE-AUTH-CUSTOMER-JWT-ADMIN-001 | 客户令牌跨越管理路由信任边界 | customer-token-to-admin-route | cross_service_token_trust | customer-identity-to-administration-service, token-validation-to-route-authorization | AUTH-CUSTOMER-JWT-TO-ADMIN-001, AUTH-JWT-ACCEPTANCE-MATRIX-001 | [agent/cases/case-auth-customer-jwt-admin-001.json](case-auth-customer-jwt-admin-001.json) |
| CASE-AUTHZ-BOLA-UI-FALSE-POSITIVE-001 | 界面默认对象与真实授权边界的分离 | ui-selector-to-object-authorization | bola | account-to-business-object, ui-selection-to-server-object-authorization | AUTHZ-BOLA-UI-FALSE-POSITIVE-001 | [agent/cases/case-authz-bola-ui-false-positive-001.json](case-authz-bola-ui-false-positive-001.json) |
| CASE-AUTHZ-EXPORT-LOG-FIELD-BOUNDARY-001 | 导出与日志读取面的字段授权边界 | normal-view-to-export-log-field-boundary | field_level_authorization_bypass | normal-view-to-export-dto, role-to-sensitive-field | AUTHZ-EXPORT-LOG-FIELD-BOUNDARY-001 | [agent/cases/case-authz-export-log-field-boundary-001.json](case-authz-export-log-field-boundary-001.json) |
| CASE-AUTHZ-MASS-ASSIGNMENT-001 | 资料更新接口的隐藏字段写入边界 | profile-field-write-boundary | mass_assignment | client-allowed-fields-to-server-domain-object, user-role-to-sensitive-profile-field | AUTHZ-MASS-ASSIGNMENT-001 | [agent/cases/case-authz-mass-assignment-001.json](case-authz-mass-assignment-001.json) |
| CASE-FILE-GUEST-UPLOAD-TICKET-001 | 游客上传票据的缺省约束差分 | guest-upload-ticket-fail-open-contract | guest_upload_ticket_fail_open | anonymous-to-storage, ticket-to-object-policy | FILE-GUEST-UPLOAD-TICKET-001 | [agent/cases/case-file-guest-upload-ticket-001.json](case-file-guest-upload-ticket-001.json) |
| CASE-INJECTION-ORDER-BY-BOOLEAN-ORACLE-001 | ORDER BY 表达式的稳定布尔 Oracle | order-by-expression-evaluation-contract | order_by_expression_injection | sort-parameter-to-query-expression | INJECTION-ORDER-BY-BOOLEAN-ORACLE-001 | [agent/cases/case-injection-order-by-boolean-oracle-001.json](case-injection-order-by-boolean-oracle-001.json) |
| CASE-INTEGRATION-BLIND-SSRF-MEDIA-001 | 媒体处理链的盲 SSRF 回连归因 | media-processor-oast-attribution-contract | server_side_remote_fetch_validation | browser-to-server-fetch, user-url-to-media-processor | INTEGRATION-BLIND-SSRF-MEDIA-001 | [agent/cases/case-integration-blind-ssrf-media-001.json](case-integration-blind-ssrf-media-001.json) |
| CASE-INTEGRATION-THIRD-PARTY-SECRET-VALIDATION-001 | 第三方服务 Secret 的等长负控验证 | third-party-server-secret-validation-contract | third_party_server_secret_exposure | public-artifact-to-provider-control-plane, server-secret-to-application-identity | INTEGRATION-THIRD-PARTY-SECRET-VALIDATION-001 | [agent/cases/case-integration-third-party-secret-validation-001.json](case-integration-third-party-secret-validation-001.json) |
| CASE-INTEGRATION-WEBSOCKET-PATH-IDENTITY-001 | WebSocket 路径身份与业务帧路由边界 | websocket-path-identity-routing-contract | websocket_path_identity_trust | anonymous-to-peer-identity, path-identity-to-business-channel | INTEGRATION-WEBSOCKET-PATH-IDENTITY-001 | [agent/cases/case-integration-websocket-path-identity-001.json](case-integration-websocket-path-identity-001.json) |

## 多维检索

### `scene`

| 值 | Case |
|---|---|
| customer-token-to-admin-route | `CASE-AUTH-CUSTOMER-JWT-ADMIN-001` |
| guest-upload-ticket-fail-open-contract | `CASE-FILE-GUEST-UPLOAD-TICKET-001` |
| media-processor-oast-attribution-contract | `CASE-INTEGRATION-BLIND-SSRF-MEDIA-001` |
| normal-view-to-export-log-field-boundary | `CASE-AUTHZ-EXPORT-LOG-FIELD-BOUNDARY-001` |
| order-by-expression-evaluation-contract | `CASE-INJECTION-ORDER-BY-BOOLEAN-ORACLE-001` |
| profile-field-write-boundary | `CASE-AUTHZ-MASS-ASSIGNMENT-001` |
| third-party-server-secret-validation-contract | `CASE-INTEGRATION-THIRD-PARTY-SECRET-VALIDATION-001` |
| ui-selector-to-object-authorization | `CASE-AUTHZ-BOLA-UI-FALSE-POSITIVE-001` |
| websocket-path-identity-routing-contract | `CASE-INTEGRATION-WEBSOCKET-PATH-IDENTITY-001` |

### `target_type`

| 值 | Case |
|---|---|
| admin-api | `CASE-AUTHZ-EXPORT-LOG-FIELD-BOUNDARY-001` |
| api-gateway | `CASE-AUTH-CUSTOMER-JWT-ADMIN-001` |
| artifact | `CASE-INTEGRATION-THIRD-PARTY-SECRET-VALIDATION-001` |
| mobile-api | `CASE-FILE-GUEST-UPLOAD-TICKET-001`, `CASE-INTEGRATION-THIRD-PARTY-SECRET-VALIDATION-001`, `CASE-INTEGRATION-WEBSOCKET-PATH-IDENTITY-001` |
| single-page-application | `CASE-AUTHZ-BOLA-UI-FALSE-POSITIVE-001`, `CASE-AUTHZ-EXPORT-LOG-FIELD-BOUNDARY-001`, `CASE-FILE-GUEST-UPLOAD-TICKET-001`, `CASE-INTEGRATION-BLIND-SSRF-MEDIA-001` |
| third-party-api | `CASE-INTEGRATION-THIRD-PARTY-SECRET-VALIDATION-001` |
| web-api | `CASE-AUTH-CUSTOMER-JWT-ADMIN-001`, `CASE-AUTHZ-BOLA-UI-FALSE-POSITIVE-001`, `CASE-AUTHZ-EXPORT-LOG-FIELD-BOUNDARY-001`, `CASE-AUTHZ-MASS-ASSIGNMENT-001`, `CASE-FILE-GUEST-UPLOAD-TICKET-001`, `CASE-INJECTION-ORDER-BY-BOOLEAN-ORACLE-001`, `CASE-INTEGRATION-BLIND-SSRF-MEDIA-001` |
| websocket | `CASE-INTEGRATION-WEBSOCKET-PATH-IDENTITY-001` |

### `technology`

| 值 | Case |
|---|---|
| bearer-token | `CASE-AUTH-CUSTOMER-JWT-ADMIN-001` |
| csv | `CASE-AUTHZ-EXPORT-LOG-FIELD-BOUNDARY-001` |
| hmac | `CASE-INTEGRATION-THIRD-PARTY-SECRET-VALIDATION-001` |
| http | `CASE-INTEGRATION-BLIND-SSRF-MEDIA-001` |
| json | `CASE-AUTHZ-BOLA-UI-FALSE-POSITIVE-001`, `CASE-AUTHZ-MASS-ASSIGNMENT-001`, `CASE-INTEGRATION-WEBSOCKET-PATH-IDENTITY-001` |
| jwt | `CASE-AUTH-CUSTOMER-JWT-ADMIN-001` |
| media-processor | `CASE-INTEGRATION-BLIND-SSRF-MEDIA-001` |
| multipart | `CASE-FILE-GUEST-UPLOAD-TICKET-001` |
| oast | `CASE-INTEGRATION-BLIND-SSRF-MEDIA-001` |
| oauth | `CASE-INTEGRATION-THIRD-PARTY-SECRET-VALIDATION-001` |
| object-storage | `CASE-FILE-GUEST-UPLOAD-TICKET-001` |
| provider-api | `CASE-INTEGRATION-THIRD-PARTY-SECRET-VALIDATION-001` |
| rest | `CASE-AUTH-CUSTOMER-JWT-ADMIN-001`, `CASE-AUTHZ-BOLA-UI-FALSE-POSITIVE-001`, `CASE-AUTHZ-EXPORT-LOG-FIELD-BOUNDARY-001`, `CASE-AUTHZ-MASS-ASSIGNMENT-001`, `CASE-FILE-GUEST-UPLOAD-TICKET-001`, `CASE-INJECTION-ORDER-BY-BOOLEAN-ORACLE-001` |
| sql | `CASE-INJECTION-ORDER-BY-BOOLEAN-ORACLE-001` |
| web-ui | `CASE-AUTHZ-BOLA-UI-FALSE-POSITIVE-001` |
| websocket | `CASE-INTEGRATION-WEBSOCKET-PATH-IDENTITY-001` |
| xlsx | `CASE-AUTHZ-EXPORT-LOG-FIELD-BOUNDARY-001` |

### `business_object`

| 值 | Case |
|---|---|
| administrative-record | `CASE-AUTH-CUSTOMER-JWT-ADMIN-001` |
| application-identity | `CASE-INTEGRATION-THIRD-PARTY-SECRET-VALIDATION-001` |
| contact-field | `CASE-AUTHZ-EXPORT-LOG-FIELD-BOUNDARY-001` |
| customer-directory | `CASE-AUTH-CUSTOMER-JWT-ADMIN-001` |
| document-preview | `CASE-INTEGRATION-BLIND-SSRF-MEDIA-001` |
| entitlement-counter | `CASE-AUTHZ-MASS-ASSIGNMENT-001` |
| export-record | `CASE-AUTHZ-EXPORT-LOG-FIELD-BOUNDARY-001` |
| integration | `CASE-INTEGRATION-THIRD-PARTY-SECRET-VALIDATION-001` |
| message | `CASE-INTEGRATION-WEBSOCKET-PATH-IDENTITY-001` |
| object | `CASE-FILE-GUEST-UPLOAD-TICKET-001` |
| operation-log | `CASE-AUTHZ-EXPORT-LOG-FIELD-BOUNDARY-001` |
| paginated-list | `CASE-INJECTION-ORDER-BY-BOOLEAN-ORACLE-001` |
| peer | `CASE-INTEGRATION-WEBSOCKET-PATH-IDENTITY-001` |
| project | `CASE-AUTHZ-BOLA-UI-FALSE-POSITIVE-001` |
| provider-credential | `CASE-INTEGRATION-THIRD-PARTY-SECRET-VALIDATION-001` |
| remote-image | `CASE-INTEGRATION-BLIND-SSRF-MEDIA-001` |
| remote-resource | `CASE-INTEGRATION-BLIND-SSRF-MEDIA-001` |
| search-result | `CASE-INJECTION-ORDER-BY-BOOLEAN-ORACLE-001` |
| tenant-resource | `CASE-AUTHZ-BOLA-UI-FALSE-POSITIVE-001` |
| terminal | `CASE-INTEGRATION-WEBSOCKET-PATH-IDENTITY-001` |
| upload-ticket | `CASE-FILE-GUEST-UPLOAD-TICKET-001` |
| user-profile | `CASE-AUTHZ-MASS-ASSIGNMENT-001` |

### `operation_type`

| 值 | Case |
|---|---|
| authenticate | `CASE-INTEGRATION-THIRD-PARTY-SECRET-VALIDATION-001` |
| callback | `CASE-INTEGRATION-BLIND-SSRF-MEDIA-001` |
| export | `CASE-AUTHZ-EXPORT-LOG-FIELD-BOUNDARY-001` |
| list | `CASE-AUTH-CUSTOMER-JWT-ADMIN-001`, `CASE-AUTHZ-BOLA-UI-FALSE-POSITIVE-001` |
| read | `CASE-AUTH-CUSTOMER-JWT-ADMIN-001`, `CASE-AUTHZ-BOLA-UI-FALSE-POSITIVE-001`, `CASE-AUTHZ-EXPORT-LOG-FIELD-BOUNDARY-001`, `CASE-INJECTION-ORDER-BY-BOOLEAN-ORACLE-001`, `CASE-INTEGRATION-BLIND-SSRF-MEDIA-001`, `CASE-INTEGRATION-THIRD-PARTY-SECRET-VALIDATION-001`, `CASE-INTEGRATION-WEBSOCKET-PATH-IDENTITY-001` |
| readback | `CASE-AUTHZ-MASS-ASSIGNMENT-001`, `CASE-FILE-GUEST-UPLOAD-TICKET-001` |
| sort | `CASE-INJECTION-ORDER-BY-BOOLEAN-ORACLE-001` |
| subscribe | `CASE-INTEGRATION-WEBSOCKET-PATH-IDENTITY-001` |
| update | `CASE-AUTHZ-MASS-ASSIGNMENT-001` |
| upload | `CASE-FILE-GUEST-UPLOAD-TICKET-001` |

### `trust_boundary`

| 值 | Case |
|---|---|
| account-to-business-object | `CASE-AUTHZ-BOLA-UI-FALSE-POSITIVE-001` |
| anonymous-to-peer-identity | `CASE-INTEGRATION-WEBSOCKET-PATH-IDENTITY-001` |
| anonymous-to-storage | `CASE-FILE-GUEST-UPLOAD-TICKET-001` |
| browser-to-server-fetch | `CASE-INTEGRATION-BLIND-SSRF-MEDIA-001` |
| client-allowed-fields-to-server-domain-object | `CASE-AUTHZ-MASS-ASSIGNMENT-001` |
| customer-identity-to-administration-service | `CASE-AUTH-CUSTOMER-JWT-ADMIN-001` |
| normal-view-to-export-dto | `CASE-AUTHZ-EXPORT-LOG-FIELD-BOUNDARY-001` |
| path-identity-to-business-channel | `CASE-INTEGRATION-WEBSOCKET-PATH-IDENTITY-001` |
| public-artifact-to-provider-control-plane | `CASE-INTEGRATION-THIRD-PARTY-SECRET-VALIDATION-001` |
| role-to-sensitive-field | `CASE-AUTHZ-EXPORT-LOG-FIELD-BOUNDARY-001` |
| server-secret-to-application-identity | `CASE-INTEGRATION-THIRD-PARTY-SECRET-VALIDATION-001` |
| sort-parameter-to-query-expression | `CASE-INJECTION-ORDER-BY-BOOLEAN-ORACLE-001` |
| ticket-to-object-policy | `CASE-FILE-GUEST-UPLOAD-TICKET-001` |
| token-validation-to-route-authorization | `CASE-AUTH-CUSTOMER-JWT-ADMIN-001` |
| ui-selection-to-server-object-authorization | `CASE-AUTHZ-BOLA-UI-FALSE-POSITIVE-001` |
| user-role-to-sensitive-profile-field | `CASE-AUTHZ-MASS-ASSIGNMENT-001` |
| user-url-to-media-processor | `CASE-INTEGRATION-BLIND-SSRF-MEDIA-001` |

### `observed_signal`

| 值 | Case |
|---|---|
| anonymous-protocol-upgrade | `CASE-INTEGRATION-WEBSOCKET-PATH-IDENTITY-001` |
| boolean-condition-changes-order | `CASE-INJECTION-ORDER-BY-BOOLEAN-ORACLE-001` |
| candidate-server-secret | `CASE-INTEGRATION-THIRD-PARTY-SECRET-VALIDATION-001` |
| client-token-accepted-by-administration-route | `CASE-AUTH-CUSTOMER-JWT-ADMIN-001` |
| default-option-contains-object-identifier | `CASE-AUTHZ-BOLA-UI-FALSE-POSITIVE-001` |
| equal-length-wrong-secret-control | `CASE-INTEGRATION-THIRD-PARTY-SECRET-VALIDATION-001` |
| export-or-log-route-is-visible | `CASE-AUTHZ-EXPORT-LOG-FIELD-BOUNDARY-001` |
| field-set-differs-between-read-surfaces | `CASE-AUTHZ-EXPORT-LOG-FIELD-BOUNDARY-001` |
| global-selector-lists-unassigned-objects | `CASE-AUTHZ-BOLA-UI-FALSE-POSITIVE-001` |
| guest-upload-ticket-route | `CASE-FILE-GUEST-UPLOAD-TICKET-001` |
| identity-in-websocket-path | `CASE-INTEGRATION-WEBSOCKET-PATH-IDENTITY-001` |
| media-user-agent-or-range | `CASE-INTEGRATION-BLIND-SSRF-MEDIA-001` |
| missing-and-fixed-invalid-token-are-rejected | `CASE-AUTH-CUSTOMER-JWT-ADMIN-001` |
| missing-file-constraints | `CASE-FILE-GUEST-UPLOAD-TICKET-001` |
| normal-read-denies-a-protected-field | `CASE-AUTHZ-EXPORT-LOG-FIELD-BOUNDARY-001` |
| normal-ui-submits-a-field-subset | `CASE-AUTHZ-MASS-ASSIGNMENT-001` |
| object-parameter-can-be-replaced | `CASE-AUTHZ-BOLA-UI-FALSE-POSITIVE-001` |
| official-validation-endpoint | `CASE-INTEGRATION-THIRD-PARTY-SECRET-VALIDATION-001` |
| public-object-url | `CASE-FILE-GUEST-UPLOAD-TICKET-001` |
| remote-url-parameter | `CASE-INTEGRATION-BLIND-SSRF-MEDIA-001` |
| response-model-exposes-additional-writable-looking-fields | `CASE-AUTHZ-MASS-ASSIGNMENT-001` |
| same-token-family-used-by-different-service-roles | `CASE-AUTH-CUSTOMER-JWT-ADMIN-001` |
| server-business-frame | `CASE-INTEGRATION-WEBSOCKET-PATH-IDENTITY-001` |
| server-correlated-oast-callback | `CASE-INTEGRATION-BLIND-SSRF-MEDIA-001` |
| stable-dual-sort-fingerprint | `CASE-INJECTION-ORDER-BY-BOOLEAN-ORACLE-001` |
| user-controlled-sort-expression | `CASE-INJECTION-ORDER-BY-BOOLEAN-ORACLE-001` |
| whole-object-update-handler | `CASE-AUTHZ-MASS-ASSIGNMENT-001` |

### `root_cause_family`

| 值 | Case |
|---|---|
| bola | `CASE-AUTHZ-BOLA-UI-FALSE-POSITIVE-001` |
| cross_service_token_trust | `CASE-AUTH-CUSTOMER-JWT-ADMIN-001` |
| field_level_authorization_bypass | `CASE-AUTHZ-EXPORT-LOG-FIELD-BOUNDARY-001` |
| guest_upload_ticket_fail_open | `CASE-FILE-GUEST-UPLOAD-TICKET-001` |
| mass_assignment | `CASE-AUTHZ-MASS-ASSIGNMENT-001` |
| order_by_expression_injection | `CASE-INJECTION-ORDER-BY-BOOLEAN-ORACLE-001` |
| server_side_remote_fetch_validation | `CASE-INTEGRATION-BLIND-SSRF-MEDIA-001` |
| third_party_server_secret_exposure | `CASE-INTEGRATION-THIRD-PARTY-SECRET-VALIDATION-001` |
| websocket_path_identity_trust | `CASE-INTEGRATION-WEBSOCKET-PATH-IDENTITY-001` |

### `evidence_mode`

| 值 | Case |
|---|---|
| account-object-mapping | `CASE-AUTHZ-BOLA-UI-FALSE-POSITIVE-001` |
| authentication-differential | `CASE-AUTH-CUSTOMER-JWT-ADMIN-001` |
| boolean-oracle | `CASE-INJECTION-ORDER-BY-BOOLEAN-ORACLE-001` |
| browser-api-differential | `CASE-AUTHZ-BOLA-UI-FALSE-POSITIVE-001` |
| callback-correlation | `CASE-INTEGRATION-BLIND-SSRF-MEDIA-001` |
| controlled-peer-differential | `CASE-INTEGRATION-WEBSOCKET-PATH-IDENTITY-001` |
| controlled-test-object | `CASE-FILE-GUEST-UPLOAD-TICKET-001` |
| controlled-write | `CASE-AUTHZ-MASS-ASSIGNMENT-001` |
| credential-classification | `CASE-INTEGRATION-THIRD-PARTY-SECRET-VALIDATION-001` |
| field-set-differential | `CASE-AUTHZ-EXPORT-LOG-FIELD-BOUNDARY-001` |
| minimal-export | `CASE-AUTHZ-EXPORT-LOG-FIELD-BOUNDARY-001` |
| minimal-pagination | `CASE-AUTH-CUSTOMER-JWT-ADMIN-001` |
| negative-control | `CASE-AUTH-CUSTOMER-JWT-ADMIN-001`, `CASE-AUTHZ-BOLA-UI-FALSE-POSITIVE-001`, `CASE-AUTHZ-MASS-ASSIGNMENT-001`, `CASE-INTEGRATION-BLIND-SSRF-MEDIA-001` |
| order-fingerprint | `CASE-INJECTION-ORDER-BY-BOOLEAN-ORACLE-001` |
| protocol-capture | `CASE-INTEGRATION-WEBSOCKET-PATH-IDENTITY-001` |
| provider-response-differential | `CASE-INTEGRATION-THIRD-PARTY-SECRET-VALIDATION-001` |
| restricted-material-reference | `CASE-INTEGRATION-THIRD-PARTY-SECRET-VALIDATION-001` |
| server-frame-correlation | `CASE-INTEGRATION-WEBSOCKET-PATH-IDENTITY-001` |
| state-readback | `CASE-AUTHZ-MASS-ASSIGNMENT-001`, `CASE-FILE-GUEST-UPLOAD-TICKET-001` |
| ticket-differential | `CASE-FILE-GUEST-UPLOAD-TICKET-001` |
| unique-oast-path | `CASE-INTEGRATION-BLIND-SSRF-MEDIA-001` |
| zero-raw-value | `CASE-AUTHZ-EXPORT-LOG-FIELD-BOUNDARY-001`, `CASE-INJECTION-ORDER-BY-BOOLEAN-ORACLE-001` |

### `required_material`

| 值 | Case |
|---|---|
| candidate-secret-fingerprint-in-restricted-evidence | `CASE-INTEGRATION-THIRD-PARTY-SECRET-VALIDATION-001` |
| confirmed-application-identity | `CASE-INTEGRATION-THIRD-PARTY-SECRET-VALIDATION-001` |
| controlled-account | `CASE-AUTHZ-MASS-ASSIGNMENT-001` |
| controlled-account-a | `CASE-AUTHZ-BOLA-UI-FALSE-POSITIVE-001` |
| controlled-account-b-or-authoritative-mapping | `CASE-AUTHZ-BOLA-UI-FALSE-POSITIVE-001` |
| controlled-low-privilege-account | `CASE-AUTHZ-EXPORT-LOG-FIELD-BOUNDARY-001` |
| controlled-low-privilege-token | `CASE-AUTH-CUSTOMER-JWT-ADMIN-001` |
| controlled-oast-endpoint | `CASE-INTEGRATION-BLIND-SSRF-MEDIA-001` |
| controlled-peer-identity | `CASE-INTEGRATION-WEBSOCKET-PATH-IDENTITY-001` |
| controlled-small-file | `CASE-FILE-GUEST-UPLOAD-TICKET-001` |
| exact-delete-or-expiry-path | `CASE-FILE-GUEST-UPLOAD-TICKET-001` |
| fixed-invalid-token | `CASE-AUTH-CUSTOMER-JWT-ADMIN-001` |
| fixed-minimal-page | `CASE-INJECTION-ORDER-BY-BOOLEAN-ORACLE-001` |
| independent-readback-route | `CASE-AUTHZ-MASS-ASSIGNMENT-001` |
| known-normal-ticket-request | `CASE-FILE-GUEST-UPLOAD-TICKET-001` |
| known-protected-read-route | `CASE-AUTH-CUSTOMER-JWT-ADMIN-001` |
| minimal-controlled-object-scope | `CASE-AUTHZ-EXPORT-LOG-FIELD-BOUNDARY-001` |
| nonempty-self-object | `CASE-AUTHZ-BOLA-UI-FALSE-POSITIVE-001` |
| official-readonly-or-validate-only-endpoint | `CASE-INTEGRATION-THIRD-PARTY-SECRET-VALIDATION-001` |
| offline-handshake-and-frame-structure | `CASE-INTEGRATION-WEBSOCKET-PATH-IDENTITY-001` |
| one-unique-path-per-request | `CASE-INTEGRATION-BLIND-SSRF-MEDIA-001` |
| optional-controlled-admin-context | `CASE-AUTH-CUSTOMER-JWT-ADMIN-001` |
| prefetch-observation-control | `CASE-INTEGRATION-BLIND-SSRF-MEDIA-001` |
| protected-field-denial-baseline | `CASE-AUTHZ-EXPORT-LOG-FIELD-BOUNDARY-001` |
| random-high-entropy-identity | `CASE-INTEGRATION-WEBSOCKET-PATH-IDENTITY-001` |
| real-ui-selector | `CASE-AUTHZ-BOLA-UI-FALSE-POSITIVE-001` |
| reversible-test-field | `CASE-AUTHZ-MASS-ASSIGNMENT-001` |
| stable-readonly-dataset | `CASE-INJECTION-ORDER-BY-BOOLEAN-ORACLE-001` |
| state-baseline | `CASE-AUTHZ-MASS-ASSIGNMENT-001` |
| two-distinct-legal-sort-keys | `CASE-INJECTION-ORDER-BY-BOOLEAN-ORACLE-001` |

### `matched_tactics`

| 值 | Case |
|---|---|
| AUTH-CUSTOMER-JWT-TO-ADMIN-001 | `CASE-AUTH-CUSTOMER-JWT-ADMIN-001` |
| AUTH-JWT-ACCEPTANCE-MATRIX-001 | `CASE-AUTH-CUSTOMER-JWT-ADMIN-001` |
| AUTHZ-BOLA-UI-FALSE-POSITIVE-001 | `CASE-AUTHZ-BOLA-UI-FALSE-POSITIVE-001` |
| AUTHZ-EXPORT-LOG-FIELD-BOUNDARY-001 | `CASE-AUTHZ-EXPORT-LOG-FIELD-BOUNDARY-001` |
| AUTHZ-MASS-ASSIGNMENT-001 | `CASE-AUTHZ-MASS-ASSIGNMENT-001` |
| FILE-GUEST-UPLOAD-TICKET-001 | `CASE-FILE-GUEST-UPLOAD-TICKET-001` |
| INJECTION-ORDER-BY-BOOLEAN-ORACLE-001 | `CASE-INJECTION-ORDER-BY-BOOLEAN-ORACLE-001` |
| INTEGRATION-BLIND-SSRF-MEDIA-001 | `CASE-INTEGRATION-BLIND-SSRF-MEDIA-001` |
| INTEGRATION-THIRD-PARTY-SECRET-VALIDATION-001 | `CASE-INTEGRATION-THIRD-PARTY-SECRET-VALIDATION-001` |
| INTEGRATION-WEBSOCKET-PATH-IDENTITY-001 | `CASE-INTEGRATION-WEBSOCKET-PATH-IDENTITY-001` |
