# Tiến độ triển khai package

Cập nhật: 13/10/2026. Source đang nằm trong workspace hiện tại; chưa publish
Composer package, plugin hay repository riêng. Bản `0.1.0` trong path repository
là version dùng cho phát triển, chưa phải release công khai.

## Phạm vi đã triển khai

### PHP core, browser runtime và PHP thuần

- `packages/antidetect-php`: Composer library PHP **8.1+**, PSR-4, production
  dependency chỉ `psr/clock` và `psr/log`; không require/import framework.
- Typed factory/contracts/context/policy/decision, ID chuỗi/UUID và guest nullable,
  resource generic; inspect/preflight/report, grant/block, revoke/reset/cleanup,
  fingerprint, rate/capacity limits, binding/consume theo ownership từ server.
- PDO MySQL **8.0/InnoDB**, connection riêng không persistent; scope lock và
  transaction. Lỗi nghiệp vụ commit security mutation; lỗi hạ tầng rollback.
  Logging chạy sau commit/nhả lock, lỗi logger không khôi phục quyền đã thu hồi.
- Shared browser dùng native APIs, ESM/AMD build sẵn và LESS làm source style.
  Pending trong suốt/inert; chỉ Block đã xác nhận hiện màn trắng; page không
  thuộc rule không gọi SDK. Timed pass dùng deadline backend, Always kiểm tra
  mỗi lần tải trang được bảo vệ; active Block bỏ qua SDK.
- Ví dụ CLI và [web PHP thuần](../examples/plain-php/web/README.md) chạy độc lập,
  có identity/session, CSRF, persistence và backend resource enforcement.

Ngày 13/10 đã nối verifier Ed25519 collect v2 theo source Shopify mới, gồm
canonical payload, Ed25519 SPKI PEM, base64url và freshness qua PSR clock.
Magento dùng verifier ở mọi environment, bắt buộc key khi admin bật protection,
gửi full signed payload qua JSON snapshot và thu hồi pass khi chữ ký sai. Pass
không vượt signed timestamp + interval; block mới giữ deadline từ signed time.
Fingerprint v2 buộc pass cũ check lại, giữ block; không thêm schema.

Core không tự intercept page: ứng dụng chọn rule, cung cấp danh tính/cấu hình,
thực thi quyết định và xử lý HTTP/cache. Không cần adapter để gọi API bằng PHP.

Rà soát core ngày 09/10: sửa wildcard nhiều dấu `*` bị regex bỏ sót khi vượt
backtracking limit; 836.400 cặp path/rule đối chiếu khớp ngữ nghĩa cũ. Report giảm
ghi session 2 → 1 lần, giữ atomic revoke/rollback; chỉ sửa hai file runtime,
không thêm file hoặc dependency. Composer consumer sạch cài đúng source mới.

### Magento đã chuyển sang package

Module `app/code/Hachitech/AntidetectBrowser` require core qua Composer.
`Model/Access` chỉ map store/customer/browser/quote; `StateRepository` và
`StoreLock` thực thi contracts bằng ResourceConnection/LockManager native.
Config, HTTP, CSRF, ACL, quote/order hooks, FPC/Varnish, cron và admin UI vẫn
thuộc module. Guard được wiring bằng virtual type riêng, không preference
global cho contracts của package.

Đã xóa `Model/Policy.php`, `Model/AccessService.php`, `Model/AccessException.php`,
`Test/Unit/Model/PolicyTest.php` và `view/frontend/web/js/interaction-lock.js`.
State machine/browser tests dùng chung chuyển vào core. Lần dọn ngày 09/10
xóa thêm HttpStatus, map HTTP tại luồng controller Check/Verdict dùng chung. Entry `access.js`
chỉ thêm form key, dịch và nhận diện action Magento; load qua RequireJS/native
initialization. `_module.less` import LESS dùng chung đã publish.

Đã bỏ việc Bootstrap/JS tự tính lại phạm vi trang: PageRules quyết định,
JavaScript dùng pageProtected từ PHP. Chỉ chọn Product thì homepage/CMS không
xuất initializer; Cart/Checkout/Complete order vẫn có hook chờ tương tác.
Custom path/Complete order không còn tra URL Rewrite khi không cần (1 → 0
lần gọi dependency mỗi path không khớp). Textarea path giữ rule `0` lúc đọc
và validate POST. Dropdown lấy danh sách hợp lệ từ core, giữ nhãn dịch Magento.
Đợt tiếp bỏ wrapper Config::protects/customerId, tái dùng policy, bỏ validate
quote lặp và giảm kiểm tra grant đặt đơn 2 → 1 khi cùng bật hai điểm; giảm thêm
22 dòng runtime, không thêm file chạy module. Source module có 63 file, gồm 49 runtime, 11 test và 3 tài liệu; Composer archive
50 file giữ README, loại Test/AUDIT/plan. Chi tiết trong
[báo cáo module](../../../app/code/Hachitech/AntidetectBrowser/AUDIT.md).

Giữ ba bảng cũ, hash visitor/customer và deadline block; chỉ thêm cột
`verification` vào session. Pass fingerprint cũ cần recheck. Rate bucket có
namespace mới nên cutover bắt đầu counter mới trong cửa sổ tối đa 60 giây.
Integration kiểm tra legacy block/quote state; **chưa diễn tập rollback đầy đủ**.

DI compile và static deploy theme `Troyclancy/default`, locale `en_AU` đã chạy.
Runtime AMD đang phục vụ khớp source package; old interaction-lock đã bỏ khỏi
generated assets của module; CSS theme có pending/block style từ LESS mới.
Ngày 09/10 đã compile DI lại, xuất bản riêng JS entry bằng DeployStaticFile
cho Troyclancy/default và Magento/blank en_AU, clean config/layout/block_html/
full_page; không biên dịch lại CSS theme đang có thay đổi ngoài module.

Lưu ý database local: lần `setup:upgrade` cũng áp thay đổi schema đã tồn tại
của Mageplaza OSC tại `sales_order.osc_survey_question`. Schema diff hiện chỉ
còn `modify_column` cho cột OSC đó; cột `verification` của module đã có.
Không coi global `setup:db:status` là PASS và không sửa tiếp schema OSC trong
phạm vi này. Không thay cấu hình bật bảo vệ của store.

### WordPress và Laravel

- [Plugin WordPress](../../antidetect-wordpress/README.md): PHP **8.1+**,
  WordPress **7.1.3**, MySQL 8/InnoDB, single-site. Settings API với nhóm key
  ngay dưới Environment, REST permission callbacks, browser-bound guest nonce,
  native logged-in REST nonce, signed HttpOnly identity cookie, reset bằng
  capability/nonce và cron native. Chặn public page ở `parse_request`; ESM qua
  script-module API, initial inert qua native HTML API. Storage `$wpdb` connection
  riêng từ chối reconnect để không ghi ngoài transaction/lock đã mất.
- Có lệnh publish assets/check và build ZIP development với vendor `--no-dev`.
  ZIP đã cài thử trên WordPress thật, không cần vendor Magento. Mất vendor khi
  protection đang bật trả 503, không trả nội dung trang gốc.
- [Ví dụ Laravel](../../antidetect-laravel-example/README.md): Laravel
  **12.69.3 / PHP 8.2+**, dùng core trực tiếp qua native service provider,
  middleware web, session/auth, CSRF, Blade và MySQL connector. Core vẫn hỗ trợ
  PHP 8.1; yêu cầu của Laravel không truyền ngược vào core.
- Ví dụ Laravel có public/protected page, check/verdict và action assert/consume;
  tắt protection không resolve storage hoặc chặn nghiệp vụ mẫu. Các backend
  resource đặc thù dự án phải nối hook riêng theo guide; plugin cơ bản không
  require WooCommerce và chưa có commerce/multisite integration.

## Kết quả kiểm tra local

Đợt chữ ký 13/10: core PHP 8.1/8.2 cùng MySQL/HTTP đạt **175 test / 812 assertion**;
Magento unit **121 test / 281 assertion**; browser + Magento entry **41 test**.
PHPStan mức 8, PSR-12, Magento coding standard runtime và Composer validate đạt.
Kiểm tra vector thật HideGuard, vector Node độc lập, tampering/key/environment/
clock-skew/expiry/replay deadline và thiếu sodium đều đạt. Các kết quả 09/10
của WordPress/Laravel bên dưới là lịch sử; adapter này chưa chuyển sang verifier
chữ ký mới trong yêu cầu hiện tại.
Native integration đạt cả signed Production HTTP/quote binding và committed
revocation, ngoài các checks DI/XML/cache/401 trước đó. Archive mới cài bằng
Composer `--no-dev` vào consumer sạch và xác minh vector thật mà không có framework.
Verdict groups đã gom vào ba public constants của `VerdictPolicy`, khớp JSON
Shopify; regression PHP 8.1/8.2 và integration Magento sau refactor đều đạt.
Nghiệm thu đợt chữ ký: **tester PASS, reviewer APPROVED**; đối chiếu PHP 8.1/
PSR-4, contract collect v2 từ source Shopify, sodium native và DI/HTTP/RequireJS Magento.


Các kết quả dưới đây là những lần chạy đã quan sát trong triển khai hiện tại;
không cộng số test baseline cũ vào nghiệm thu mới. MySQL/HTTP suites không skip.

| Kiểm tra | Kết quả |
| --- | --- |
| Core PHP 8.1 + MySQL thật + PHP web HTTP | 175 test / 812 assertion |
| Core PHP 8.2 + MySQL thật + PHP web HTTP | 175 test / 812 assertion |
| Core PHPStan mức 8, PSR-12, Composer strict | Đạt |
| Core Composer `--no-dev` / archive | Core + đúng hai PSR dependency; autoload không boot framework; không kèm dev vendor/tests/node_modules |
| Browser + Magento entry | 41 Node test; build/publish `--check` đạt |
| Magento unit PHP 8.2 | 121 test / 281 assertion |
| Magento integration native | PASS: DI/XML, page/cache hook order, 401/expiry, legacy block, quote binding/consume, storage/atomic, Product-only homepage không init và deferred action init |
| Magento DI/static/cache | Compile/JS publish/cache clean ngày 09/10 đạt; source và served AMD trùng hash; giữ CSS từ deploy trước |
| Magento Composer archive | 50 file; runtime/README đầy đủ, loại test/tài liệu nội bộ/lớp đã xóa |
| Magento PHP/PHTML coding standard | 0 lỗi; còn 1 warning `base64_decode` của Bootstrap đã tồn tại |
| WordPress PHP 8.1 + MySQL/HTTP | 32 test / 352 assertion |
| WordPress PHP 8.2 + MySQL/HTTP với ZIP vendor riêng | 32 test / 352 assertion |
| WordPress concurrency/connection loss | 6 worker: đúng 3 pass, 3 rate-limited; lost connection rollback, không reconnect |
| WordPress install/distribution | Fresh fixture installer, activation/dbDelta, ZIP no-dev/autoload/assets, missing-vendor 503 đạt |
| WordPress admin/REST | Login/settings/reset capability+nonce, CSRF/body limit, pass/block/deadline, signed environment 501 đạt |
| Laravel PHP 8.2 | 8 test / 70 assertion: native TestCase + HTTP session/CSRF/resource/401, disabled policy, storage failure, Symfony response |
| WordPress/Laravel lint và Composer strict | Đạt |

Nghiệm thu phạm vi development đã triển khai: **tester PASS, reviewer APPROVED**.
Review đối chiếu core PHP 8.1/PSR-4/contracts, Magento 2.4.7-p10 DI/XML/
RequireJS/LESS, WordPress 7.1.3 native APIs và Laravel 12 native lifecycle.
Các giới hạn release bên dưới nằm ngoài kết luận này; đây không phải nghiệm
thu production hoặc tuyên bố hoàn tất toàn bộ kế hoạch.

## Còn lại trước production/phát hành

1. **Session/replay binding:** chữ ký v2 đã triển khai và Magento không còn
   từ chối Staging/Production mặc định bằng HTTP 501. Request ID được ký nhưng
   payload chưa có server nonce/browser/actor identity; không có replay store
   single-use. Key cấu hình được giả định cấp riêng cho một site, giống app nguồn.
   Freshness/deadline hạn chế reuse theo thời gian, chưa chống transfer giữa
   browser trong cửa sổ đó. Xem [contract](CONTRACT.md). WordPress/Laravel và
   demo PHP vẫn dùng DevelopmentVerifier opt-in, chưa chuyển sang ký response.
2. SDK HideGuard thật/site key thật, browser thật, Magento order thực tế và
   reverse proxy/Varnish/CDN/page-cache thực tế chưa được kiểm thử end-to-end.
   PHP không chặn được HTML đã được cache trả trước PHP. WordPress
   `advanced-cache.php` cần bypass/purge/tích hợp riêng; native headers chưa đủ.
3. ZIP WordPress development đang bundle dependency chưa prefix. Public ZIP
   cần namespace scoping và collision tests trước phân phối; multisite và
   WooCommerce chỉ thêm khi có yêu cầu riêng.
4. Diễn tập Magento upgrade/rollback trên bản sao dữ liệu có traffic; xác nhận
   deployment/database baseline (gồm pending OSC schema) trước live cutover.
5. Tách repository/release source khỏi local Composer path, chốt versioning,
   chạy CI trên GitHub và compatibility matrix trước khi publish. Workflows
   đã viết chưa chạy trên GitHub; chưa kiểm chứng PHP cao hơn 8.2.

Theo dõi các bước này theo mục 11–14 trong
[kế hoạch triển khai](../../../app/code/Hachitech/AntidetectBrowser/PACKAGE_EXTRACTION_PLAN.md).

Đối chiếu lại ngày 19/10/2026: module local đã có `registration.php` và được bật
trong app config. Native Magento DI resolve `Ed25519Verifier` từ package; các
static runtime đang phục vụ khớp bản publish. HideGuard URL đã có riêng theo
environment, mặc định `https://hideguard.io`; package validate HTTPS origin và
runtime dùng nó cho cả SDK script lẫn `data-endpoint`. CSP collector global giữ
nguyên các collector native, chỉ thêm origin đang chọn ở frontend. Test native
dùng bảng/cache/generated-code fixture, kiểm tra admin fields và CSP. DI đã
compile lại, runtime được publish bằng DeployStaticFile cho hai theme local,
đổi static version và clean cache. Không chạy setup:upgrade hoặc build CSS theme.


## 2026-10-19: server-owned verification window

Core owns attempt IDs, fixed deadlines, explicit retry, SDK failure denial and
Always-mode revocation; adapters own native identity/CSRF/routing/schema/UI.
PDO setup upgrades existing session tables additively. Magento, WordPress,
Laravel and plain PHP consumers forward the same protocol. No runtime framework
or HTTP/session dependency was added to core; PHP 8.1 remains supported.

Observed checks: core 209 tests/935 assertions on PHP 8.1 and 8.2; Magento 133
unit tests/322 assertions plus isolated native integration (DI/XSD/signatures,
no-SDK expiry/retry/failure); WordPress 7.1 on PHP 8.1: 37 tests/403 assertions;
Laravel 12: 10 tests/93 assertions; shared/Magento browser: 51 tests. PHPStan
level 8 and PSR-12 passed. Magento schema upgrade, DI compilation and frontend
LESS/static deployment completed. Tester PASS; tested code review APPROVED.

Public integration changes and migration steps are documented in README,
CONTRACT and BROWSER. Attempt IDs correlate callbacks but are not signed by
HideGuard; this does not introduce cryptographic single-use/session binding.

Final deployment check: native Magento JS matches published source in both
local themes; native compiled theme CSS includes Retry styles after clearing
only affected generated assets. Cache was cleaned. Global db:status still
reports the unrelated sales_order.osc_survey_question schema drift; native
dry-run has no pending Hachitech_AntidetectBrowser DDL.

Standalone gate transition fix (2026-10-19): keep its message card/white background
visible during rechecks and after Allow until navigation replaces the document.
Normal protected-page pending remains transparent and Allow unlocks immediately.
No PHP authorization/storage/signature behavior changed. SSR marker is documented
in BROWSER; adapters and prebuilt artifacts are synchronized. Observed: 52 browser
tests, Magento native integration and Laravel 10/93 with MySQL pass; template lint,
build/publication and native served-asset checks pass. Visual QA confirms native
pending HTML is opaque before JS initializes. Tester PASS, reviewer APPROVED.

### Conformance hardening — 2026-10-26

- Guard accepts authenticated Challenge under D-03; unverified staging/production
  verdicts remain rejected. Revoking an identity, scope or resource also cancels
  its verification attempt; failed attempts still require an explicit retry.
- Default transport/client response limits are 64 KiB, including gzip expansion
  and custom-transport parsing. Added a shared private schema/expected-visitor
  checker using the same token/score/reason limits as the Node package.
- Magento delegates private checking to the core and cancels attempts in its
  existing storage adapter. No schema migration. Per owner clarification, HideGuard
  validates the registered domain/public key and backend secret; no separate
  expected-site configuration is required. Collect signature, environment and
  freshness checks remain intact. Policy fingerprint v4 invalidates old attempts
  and grants when adopting the updated revocation semantics.
- Observed on PHP 8.2.35/PHPUnit 9.6.36 in isolated container snapshots: baseline
  270 tests/1080 assertions; final package 304 tests/1205 assertions, including
  random-table MySQL fixtures, verified local HTTPS/gzip and the plain PHP web
  example; Magento unit 184 tests/444 assertions. No skipped tests in these final
  runs. PHPStan level 8 with PHP 8.1 target, PSR-12, changed Magento runtime coding
  standard, and native DI/admin XML schema validation passed.
- Tester PASS; reviewer APPROVED after checking PHP 8.1/PSR-4/PSR clock/error and
  storage contracts, Magento 2.4.7-p10 DI/config patterns, security and code quality.
  Actual PHP 8.1 runtime, live HideGuard/API/checkout and deployment were not tested.
  Application vendor/config/database records were not updated. Matching package
  and module sources must be installed together; custom storage implementations
  must adopt the updated cancellation contract.
- Final checks after removing the expected-site option: package and Magento
  PHPUnit suites, PHPStan level 8/PHP 8.1 target, PSR-12 and native XML schemas
  passed. Review APPROVED against the owner-confirmed domain/key contract;
  canonical signature verification is unchanged. Full proof session/resource
  binding still requires an upstream signed field; no full replay-prevention
  claim is made.

### PHP 8.1 CI compatibility — 2026-10-26

The direct `CURLOPT_XFERINFOFUNCTION` reference caused both an undefined constant
at runtime and the reported PHPStan failure on PHP 8.1. The option was added in
PHP 8.2. CurlTransport now detects it and uses `CURLOPT_PROGRESSFUNCTION` on PHP
8.1, preserving the same download/decompression limits and timeout behavior.

Observed with read-only snapshots and local HTTPS fixtures: 12 transport tests /
49 assertions passed on each of PHP 8.1.34 and PHP 8.2. PHPStan 1.12 level 8 passed
on actual PHP 8.1 (test CLI memory limit 512 MiB), and PSR-12 passed. Tester PASS;
reviewer APPROVED against the manifest PHP 8.1+ requirement and CI version matrix.
No PHPStan dependency upgrade or error suppression was needed. GitHub Actions
has not been rerun and the change has not been pushed.
