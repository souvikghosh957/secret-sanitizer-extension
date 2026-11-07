// Everyday pastes that must stay readable, and the real secrets that must still be caught
// after the generic rules were tightened. When adding to UNMASKED, add the nearest real secret
// to STILL_MASKED so a fix can't quietly lose coverage.
const test = require("node:test");
const assert = require("node:assert/strict");
const { loadDetector } = require("./helpers");

const d = loadDetector();

const UNMASKED = {
  "quoted names": [
    `TypeError: Cannot read properties of undefined (reading 'confirmationReference')`,
    `private static final String CONFIRMATION_QUEUE = "TradeConfirmationOutboundQueue";`,
    `String topic = "commodityTradeLifecycleEvents";`,
    `it("shouldMaskOpenAiKeyWhenPastedIntoTextarea", () => {})`,
    `const mapStateToPropsForConfirmationDialog = "mapStateToPropsForConfirmationDialog";`,
    `import { useConfirmationQueueSubscriptionHandler } from "./useConfirmationQueueSubscriptionHandler";`,
    `Traceback (most recent call last):\n  File "app.py", line 3\nModuleNotFoundError: No module named 'transformers_stream_generator'`,
  ],
  "stack traces": [
    `at com.amphora.trade.confirmation.XceptorConfirmationPublisherImpl.publish(XceptorConfirmationPublisherImpl.java:142)`,
    `Caused by: org.hibernate.exception.ConstraintViolationException: could not execute statement [ORA-00001] at org.hibernate.internal.ExceptionConverterImpl.convert(ExceptionConverterImpl.java:154)`,
    `  File "/usr/local/lib/python3.11/site-packages/sqlalchemy/engine/base.py", line 1410, in execute`,
    `goroutine 1 [running]:\nmain.(*ConfirmationPublisher).Publish(0xc000118000, {0x1400012e000, 0x1f})\n\t/app/internal/publisher.go:88 +0x1a4`,
    `    at processTicksAndRejections (node:internal/process/task_queues:95:5)\n    at async ConfirmationService.publish (/app/dist/services/confirmation.service.js:42:17)`,
  ],
  "containers and kubernetes": [
    `confirmation-worker-7d9f8b6c5-x2kqp   1/1   Running   0   3d`,
    `pod/payment-api-6c9f7d8b4-tz5rk   0/1   CrashLoopBackOff   12   40m`,
    `replicaset.apps/payment-api-6c9f7d8b4   3   3   3   4h`,
    `CONTAINER ID   IMAGE          COMMAND\n3f4e5a6b7c8d   nginx:1.25     "/docker-entrypoint.…"`,
    `Container ID: containerd://a3f1c9d2e8b7465f9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b`,
    `uid: 6f1c2d3e-4a5b-6c7d-8e9f-0a1b2c3d4e5f\nresourceVersion: "48213379"`,
    `kubectl logs deployment/confirmation-worker -n trading --tail=100`,
    `image: postgres:16-alpine`,
  ],
  "cloud resources": [
    `arn:aws:iam::482915736104:role/confirmation-pipeline-role`,
    `arn:aws:lambda:us-east-1:123456789012:function:confirmationPublisherHandler`,
    `arn:aws:s3:::my-company-production-artifacts-bucket-eu-west-1/builds/2026/app.zip`,
    `StackId: arn:aws:cloudformation:us-east-1:123456789012:stack/prod-api/51af3dc0-da77-11e4-872e-1234567890ab`,
    `/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/prod-rg/providers/Microsoft.Compute/virtualMachines/vm01`,
    `resource_id = "subnet-0a1b2c3d4e5f67890"  vpc = "vpc-0123456789abcdef0"`,
    `aws_instance.web: Creation complete after 42s [id=i-0abcd1234ef567890]`,
    `ami = "ami-0c55b159cbfafe1f0"\nsecurity_groups = ["sg-0a1b2c3d4e5f67890"]`,
  ],
  "request ids": [
    `traceId=... requestId=req_01HF8ZK3QW9X7YV2M4N6P8R0T`,
    `x-request-id: 01ARZ3NDEKTSV4RRFFQ69G5FAV`,
    `ETag: "33a64df551425fcc55e4d42a148795d9f25f8d3e"\nX-Request-Id: 7b3c9e1a-2f4d-4e6a-8b1c-9d0e1f2a3b4c`,
    `traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01`,
    `request_id: 123e4567-e89b-12d3-a456-426614174000`,
  ],
  "hashes": [
    `image: nginx@sha256:0d17b565c37bcbd895e9d92315a05c1c3c9a29f762b011a10c54a66cd53c9b31`,
    `sha256:4bc453b53cb3d914b45f4b250294236adba2c0e09ff6f03793949e7e39fd4cc1`,
    `requests==2.31.0 --hash=sha256:58cd2187c01e70e6e26505bca751777aa9f2ee0b7f4300988b709f44e013003f`,
    `md5: 9e107d9d372bb6826bd81d3542a419d6  sha1: 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12`,
    `"integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg=="`,
    `"checksum": "sha256-mxMCD3QN6Q8Fj3dFZ6gJjGkxkRCe9g9bVYJ3wFv9Y0k="`,
    `name = "certifi"\nversion = "2024.2.2"\nhash = "sha256:dc383c07b76109f368f6106eee2b593b04a011ea4d55f652c6ca24a754d1cdd1"`,
    `github.com/stretchr/testify v1.9.0 h1:HtqpIVDClZ4nwg75+xeAkDXmS7MwRV4rR/fm1Y2Ptm0=`,
    `resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#679591c564a3bffaae8454cf0b3df370c3d6911c"`,
    `content-security-policy: script-src 'nonce-rAnd0m123' 'sha256-RFWPLDbv2BY+rCkDzsE+0fr8ylGr2R2faWMhq4lfEQc='`,
    `commit 3f786850e387550fdab836ed7e6dc881de23001b\nAuthor: x`,
    `commit: 3f786850e387550fdab836ed7e6dc881de23001b`,
    `##[group]Run actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11`,
    `Run ID 8421937465 attempt 2 commit 9f8e7d6c5b4a39281706f5e4d3c2b1a098765432`,
    `Cache restored from key: Linux-node-modules-5f4dcc3b5aa765d61d8327deb882cf99`,
    `fixed in 3f78685 and a1b2c3d`,
  ],
  "embedded files and public keys": [
    `data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==`,
    `"image/png": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="`,
    `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl me@laptop`,
    `-----BEGIN CERTIFICATE-----\nMIIDdzCCAl+gAwIBAgIEbFZ7ajANBgkqhkiG9w0BAQsFADBsMRAwDgYDVQQGEwdVbmtub3duMRAw\n-----END CERTIFICATE-----`,
    `-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6\n-----END PUBLIC KEY-----`,
  ],
  "urls": [
    `https://docs.google.com/document/d/1aBcD3fGhIjKlMnOpQrStUvWxYz0123456789AbCdEf/edit`,
    `https://www.youtube.com/watch?v=dQw4w9WgXcQ&list=PLrAXtmErZgOeiKm4sgNOknGvNjby9efdf`,
    `https://mail.google.com/mail/u/0/#inbox/FMfcgzGqRGfhTmKXBsvZlFvwhDmcHfpq`,
    `https://github.com/souvikghosh957/secret-sanitizer-extension/blob/master/detector.js`,
  ],
  "indian id lookalikes": [
    `Trade 482915736104 confirmed, ref 739201846352, invoice 600123456789`,
    `variable PROD0CONFIG and HTTP0STATUS1`,
    `Invoice INVC0123456 PO ABCD0EFGHIJ code TEST0DATA12`,
    `Order number 1234 5678 9012`,
  ],
  "password-shaped text": [
    `password: must be at least 8 characters`,
    `password: \${DB_PASSWORD}`,
    `password = creds.password`,
    `password: process.env.DB_PASSWORD`,
    `git clone https://user:<password>@github.com/x/y.git`,
    `api_key: <your-key-here>`,
    `Authorization: Bearer <token>`,
  ],
  "references under secret-sounding names": [
    `secret_key = settings.DjangoProjectSecretKeyName`,
    `api_key: YOUR_API_KEY_GOES_HERE_PLEASE`,
    `token_count: 1234567890123456`,
    `public_key: 5f4dcc3b5aa765d61d8327deb882cf99`,
    `session_id: 5f4dcc3b5aa765d61d8327deb882cf99`,
    `token: xxxxxxxxxxxxxxxxxxxxxxxx`,
  ],
  "code and logs": [
    `SELECT id, created_at FROM trade_confirmations WHERE status = 'PENDING' ORDER BY created_at DESC;`,
    `function a(b,c){return b.map(function(d){return d+c})}var e=a([1,2,3],4);console.log(e);`,
    `from sklearn.model_selection import train_test_split`,
    `org.springframework.boot:spring-boot-starter-web:3.2.1`,
    `contact jane.doe@example.com for access`,
    `<IPython.core.display.Image object>\nOut[12]: array([0.12345678, 0.98765432])`,
    `<matplotlib.axes._subplots.AxesSubplot at 0x7f8b2c3d4e50>`,
    `<script src="/assets/index-Bx7dK2qP.js"></script> <link href="/static/css/main.8f3a1c2e.chunk.css">`,
    `GET /api/v1/items HTTP/1.1\nHost: api.example.com\nAccept: application/json\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36`,
    `2026-11-04T10:00:00.123456Z ERROR session=abc123 user=42 pid=3321 ThreadPoolExecutor-1_0 connection reset`,
    `src/main/java/com/example1/myapp/service2/impl/ConfirmationServiceImplementation.java`,
    `const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";`,
  ],
  "japanese (no spaces between words)": [
    `trade_idとconfirmation_referenceをorder_tableから取得しようとするとエラーになります`,
    `XceptorConfirmationPublisherImplクラスのpublishメソッドでNullPointerExceptionが発生しました`,
    `getUserNameとsetUserNameとgetOrderIdとsetOrderIdを実装してください`,
    `「confirmationReference」が見つかりません`,
    `パスワードは8文字以上にしてください`,
  ],
};

// [description, input, value that must not survive]
const STILL_MASKED = [
  // Quoted
  ["quoted base62", `const v = "Zq8xW3vR7tY2uI9oP4aS6dF1";`, "Zq8xW3vR7tY2uI9oP4aS6dF1"],
  ["quoted letters only", `const v = "qZxWvRtYuIoPaSdFgHjKlMnB";`, "qZxWvRtYuIoPaSdFgHjKlMnB"],
  ["quoted readable value under a secret name", `"client_secret": "correcthorsebatterystaple"`, "correcthorsebatterystaple"],
  // Unquoted, with and without a name
  ["bare base62", `here it is Zq8xW3vR7tY2uI9oP4aS6dF1 thanks`, "Zq8xW3vR7tY2uI9oP4aS6dF1"],
  ["16-char token", `SIGNING_KEY=Zq8xW3vR7tY2uI9o`, "Zq8xW3vR7tY2uI9o"],
  ["12-char token under a secret name", `webhook_secret: Zq8xW3vR7tY2`, "Zq8xW3vR7tY2"],
  ["dashed serial", `license aB3d-eF5g-hI7j-kL9m-nO1p`, "aB3d-eF5g-hI7j-kL9m-nO1p"],
  ["token with a readable prefix", `prod-Zq8xW3vR7tY2uI9oP4aS6dF1`, "Zq8xW3vR7tY2uI9oP4aS6dF1"],
  // Hex: only a name makes it a secret
  ["hex under a secret name", `webhook_secret: 5f4dcc3b5aa765d61d8327deb882cf99`, "5f4dcc3b5aa765d61d8327deb882cf99"],
  ["64-hex token assigned", `TOKEN=4bc453b53cb3d914b45f4b250294236adba2c0e09ff6f03793949e7e39fd4cc1`, "4bc453b53cb3d914b45f4b250294236adba2c0e09ff6f03793949e7e39fd4cc1"],
  ["40-hex under an ordinary name", `GH_OLD=3f786850e387550fdab836ed7e6dc881de23001b`, "3f786850e387550fdab836ed7e6dc881de23001b"],
  // Base64
  ["aws secret with slashes", `aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`, "wJalrXUtnFEMI"],
  ["base64 under a secret name", `"secret": "UHJvZHVjdGlvblNlY3JldEtleVZhbHVlMTIzNDU2Nzg5MA=="`, "UHJvZHVjdGlvblNlY3JldEtleVZhbHVl"],
  ["unnamed base64 blob", `blob r9Fk2Lm7+Qx4Tz/8Vb1Nc6Hs3Dp0Wy5Jg2Kt9Ae7Ru4Zo1X`, "r9Fk2Lm7"],
  // URLs: query values by parameter name, known webhooks, credentials
  ["token in a query", `https://example.com/cb?access_token=Zq8xW3vR7tY2uI9oP4aS6dF1gH5jK0lL`, "Zq8xW3vR7tY2uI9oP4aS6dF1gH5jK0lL"],
  ["short ?key= value", `https://api.example.com/v1?key=Zq8xW3vR7tY2uI9o`, "Zq8xW3vR7tY2uI9o"],
  ["signature in a query", `https://acct.blob.core.windows.net/c?sv=2022-11-02&sig=Zq8xW3vR7tY2uI9oP4aS6dF1gH5jK0lL`, "Zq8xW3vR7tY2uI9oP4aS6dF1gH5jK0lL"],
  ["token in a fragment", `https://example.com/cb#access_token=Zq8xW3vR7tY2uI9oP4aS6dF1gH5jK0lL`, "Zq8xW3vR7tY2uI9oP4aS6dF1gH5jK0lL"],
  // Settings after a URL, and names that only look harmless
  ["azure connection string", `BlobEndpoint=https://a.blob.core.windows.net/;SharedAccessSignature=Xk29fLq8mZp1Rt7vBn3GhY6wQs4JdE0aUc5oTi2N`, "Xk29fLq8mZp1Rt7vBn3GhY6wQs4JdE0aUc5oTi2N"],
  ["jdbc access token", `jdbc:sqlserver://h;accessToken=Xk29fLq8mZp1Rt7vBn3GhY6wQs4JdE0aUc5oTi2N`, "Xk29fLq8mZp1Rt7vBn3GhY6wQs4JdE0aUc5oTi2N"],
  ["secret after a comma-separated url", `urls=https://a.com/x,api_secret=Xk29fLq8mZp1Rt7vBn3GhY6wQs4JdE0aUc5oTi2N`, "Xk29fLq8mZp1Rt7vBn3GhY6wQs4JdE0aUc5oTi2N"],
  ["commented-out env line", `#GH_OLD=Xk29fLq8mZp1Rt7vBn3GhY6wQs4JdE0aUc5oTi2N`, "Xk29fLq8mZp1Rt7vBn3GhY6wQs4JdE0aUc5oTi2N"],
  ["semicolon-separated assignment", `A=1;DB_KEYX=Xk29fLq8mZp1Rt7vBn3GhY6wQs4JdE0aUc5oTi2N`, "Xk29fLq8mZp1Rt7vBn3GhY6wQs4JdE0aUc5oTi2N"],
  ["session id in a url", `https://a.com/cb?session_id=Xk29fLq8mZp1Rt7vBn3GhY6wQs4JdE0aUc5oTi2N`, "Xk29fLq8mZp1Rt7vBn3GhY6wQs4JdE0aUc5oTi2N"],
  ["auth id in a url", `https://a.com/cb?auth_id=Xk29fLq8mZp1Rt7vBn3GhY6wQs4JdE0aUc5oTi2N`, "Xk29fLq8mZp1Rt7vBn3GhY6wQs4JdE0aUc5oTi2N"],
  ["random value under an unknown parameter", `https://a.com/cb?hmac=Xk29fLq8mZp1Rt7vBn3GhY6wQs4JdE0aUc5oTi2N`, "Xk29fLq8mZp1Rt7vBn3GhY6wQs4JdE0aUc5oTi2N"],
  ["token containing an image signature", `value r0lgodXk29fLq8mZp1Rt7vBn3GhY6wQs4JdE0aUc5oTi2N`, "r0lgodXk29fLq8mZp1Rt7vBn3GhY6wQs4JdE0aUc5oTi2N"],
  ["the word secret as a password", `password=secret`, "secret"],
  ["the word password as a password", `password=password`, "password=password"],
  // Built at runtime so GitHub push protection doesn't treat the placeholder as a real webhook
  ["slack webhook", `https://hooks.slack.com/services/T00000000/B00000000/${"X".repeat(24)}`, "X".repeat(24)],
  ["teams webhook", `https://contoso.webhook.office.com/webhookb2/abc/IncomingWebhook/def/ghi`, "IncomingWebhook"],
  ["telegram bot token in a URL path", `https://api.telegram.org/bot123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsawX/getMe`, "AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsawX"],
  ["password in a URL", `https://user:hunter2xyz@internal.example.com/repo.git`, "hunter2xyz"],
  ["token as the URL username", `git clone https://Zq8xW3vR7tY2uI9oP4aS6dF1@github.com/x/y.git`, "Zq8xW3vR7tY2uI9oP4aS6dF1"],
  // Specific rules run even inside spans the generic rules skip
  ["known key inside a URL path", `https://example.com/ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789/x`, "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"],
  // Indian IDs with context
  ["aadhaar grouped, no keyword", `2341 2341 2346`, "2341 2341 2346"],
  ["aadhaar ungrouped with keyword", `Aadhaar: 234123412346`, "234123412346"],
  ["aadhaar keyword with suffix", `aadhaar_number=234123412346`, "234123412346"],
  ["aadhaar keyword after", `234123412346 is my aadhaar`, "234123412346"],
  ["uid keyword", `my uid is 234123412346`, "234123412346"],
  ["ifsc keyword", `IFSC: HDFC0001234`, "HDFC0001234"],
  ["ifsc near bank", `bank SBIN0005943 account 1234`, "SBIN0005943"],
  // Headers and keys
  ["basic auth header", `Authorization: Basic dXNlcjpwYXNzd29yZA==`, "dXNlcjpwYXNzd29yZA"],
  ["cookie values", `Cookie: sessionid=8f14e45fceea167a5a36dedd4bea2543abcdef12; csrftoken=Xy7Kp2Lm9Qr4Tv6Wz8Bn3Cd5Fg1Hj0Ks`, "Xy7Kp2Lm9Qr4Tv6Wz8Bn3Cd5Fg1Hj0Ks"],
  ["private key", `-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----`, "MIIEvQIBADAN"],
  ["encrypted private key", `-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END ENCRYPTED PRIVATE KEY-----`, "MIIEvQIBADAN"],
  ["private key cut off before END", `-----BEGIN RSA PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nabcd`, "MIIEvQIBADAN"],
  ["password next to a certificate", `-----BEGIN CERTIFICATE-----\nMIIDdzCC\n-----END CERTIFICATE-----\npassword: hunter2xyz`, "hunter2xyz"],
  // Japanese
  ["token inside a japanese sentence", `APIキーはZq8xW3vR7tY2uI9oP4aS6dF1gH5jK0lLです`, "Zq8xW3vR7tY2uI9oP4aS6dF1gH5jK0lL"],
  ["japanese password keyword", `パスワードはhunter2xyzです`, "hunter2xyz"],
  ["japanese password with colon", `パスワード:hunter2xyz`, "hunter2xyz"],
];

for (const [group, inputs] of Object.entries(UNMASKED)) {
  test(`stays readable: ${group}`, () => {
    for (const input of inputs) {
      const r = d.scan(input);
      assert.equal(r.maskedText, input, `masked as ${r.labels.join(", ")}: ${input}`);
    }
  });
}

for (const [name, input, secret] of STILL_MASKED) {
  test(`still masks: ${name}`, () => {
    assert.ok(!d.scan(input).maskedText.includes(secret));
  });
}

test("masking inside a japanese sentence leaves the sentence readable", () => {
  assert.equal(d.scan("APIキーはZq8xW3vR7tY2uI9oP4aS6dF1gH5jK0lLです").maskedText, "APIキーは[ENTROPY]です");
  assert.equal(d.scan("接続先はpostgres://admin:s3cretPw@db.internal:5432/appです").maskedText, "接続先は[DB_CONN]です");
});

test("quoted secrets keep their quotes", () => {
  assert.equal(d.scan(`const v = "Zq8xW3vR7tY2uI9oP4aS6dF1";`).maskedText, `const v = "[QUOTED_SECRET]";`);
});

// Deterministic, so a threshold change shows up as a real change rather than noise.
function seededRandom(seed) {
  return () => (seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0) / 2 ** 32;
}

test("random tokens are caught at 95%+ for every shape the generic rules handle", () => {
  const random = seededRandom(42);
  const alphabets = {
    base62: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    letters: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    lowerDigits: "abcdefghijklmnopqrstuvwxyz0123456789",
    base32: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
  };
  const placements = {
    bare: t => `here it is ${t} thanks`,
    assigned: t => `SIGNING_KEY=${t}`,
    quoted: t => `const v = "${t}";`,
    ordinaryName: t => `value: ${t}`,
  };
  for (const [alphabetName, alphabet] of Object.entries(alphabets)) {
    for (const length of [20, 32, 48]) {
      for (const [placementName, place] of Object.entries(placements)) {
        let caught = 0;
        for (let i = 0; i < 200; i++) {
          const token = Array.from({ length }, () => alphabet[Math.floor(random() * alphabet.length)]).join("");
          if (!d.scan(place(token)).maskedText.includes(token)) caught++;
        }
        assert.ok(caught >= 190, `${alphabetName}/${length}/${placementName}: ${caught}/200`);
      }
    }
  }
});

test("no pattern hangs on input shaped for backtracking, at the full-scan limit", () => {
  const size = d.DETECTOR_CONFIG.fullScanMaxLength;
  const fill = (unit) => unit.repeat(Math.ceil(size / unit.length)).slice(0, size);
  const inputs = [
    fill("a.") + "://", fill("a.") + "@", fill("a-") + "@upi",
    "otp" + " ".repeat(size - 10), "passport" + " ".repeat(size - 10), "passport" + fill("-_ ").slice(10),
    fill("postgres://:"), fill("https://a:"), fill("://a@"),
    fill("-----BEGIN PRIVATE KEY-----\n"), fill("-----BEGIN CERTIFICATE-----\n"), fill("ssh-rsa "),
    fill("password="), fill('"a'), fill("a/"), fill("a:"), fill("secret      =  "),
    "data:image/png;base64," + fill("aB3+").slice(30), fill("data:a;"),
  ];
  for (const input of inputs) {
    const start = performance.now();
    d.scan(input);
    const ms = performance.now() - start;
    assert.ok(ms < 1000, `${ms.toFixed(0)} ms on ${JSON.stringify(input.slice(0, 24))}...`);
  }
});

test("a huge data URI doesn't use up the match cap", () => {
  const r = d.scan("data:image/png;base64," + "aB3dE5gH7jK9mN1pQ3sT5vX7zA9cE1gI3kM5oQ7sU9wY1aC3eG5+".repeat(5000));
  assert.equal(r.partial, false);
  assert.equal(r.replacements.length, 0);
});

test("random-token detection can be turned off like any other rule", () => {
  const input = "SIGNING_KEY=Zq8xW3vR7tY2uI9oP4aS6dF1gH5jK0lL";
  assert.equal(d.scan(input).labels[0], "ENTROPY");
  assert.equal(d.scan(input, d.compilePatterns(d.SHARED_PATTERNS, ["ENTROPY"])).maskedText, input);
});

test("sha256Hex matches the standard implementation", () => {
  const { createHash } = require("node:crypto");
  const inputs = ["", "abc", "パスワード", "x".repeat(55), "x".repeat(56), "x".repeat(64), "x".repeat(1000)];
  for (const input of inputs) {
    assert.equal(d.sha256Hex(input), createHash("sha256").update(input).digest("hex"), JSON.stringify(input.slice(0, 20)));
  }
});

test("allowed values are dropped only from generic rules", () => {
  const salt = "c2FsdA";
  const generic = { start: 0, end: 1, label: "ENTROPY", original: "Zq8xW3vR7tY2uI9oP4aS" };
  const specific = { start: 2, end: 3, label: "OPENAI_KEY", original: "sk-proj-whatever" };
  const allowed = new Set([d.allowedValueHash(salt, generic.original), d.allowedValueHash(salt, specific.original)]);

  assert.deepEqual([...d.dropAllowedValues([generic, specific], allowed, salt)].map(m => m.label), ["OPENAI_KEY"]);
  assert.equal(d.dropAllowedValues([generic], allowed, "another-salt").length, 1, "hashes are salted");
  assert.equal(d.dropAllowedValues([generic], new Set(), salt).length, 1);
  assert.equal(d.dropAllowedValues([generic], allowed, null).length, 1);
});
