const test = require("node:test");
const assert = require("node:assert/strict");
const { loadDetector } = require("./helpers");

const d = loadDetector();

// [description, input, expected masked output]
const MASKED = [
  // Database URLs — every common scheme variant
  ["postgres URL", "postgres://admin:s3cret@db.prod.internal:5432/myapp", "[DB_CONN]"],
  ["postgresql URL keeps the key name", "DATABASE_URL=postgresql://admin:s3cretPw@db.internal:5432/app", "DATABASE_URL=[DB_CONN]"],
  ["mongodb+srv URL", "mongodb+srv://user:hunter2xyz@cluster0.mongodb.net/db", "[DB_CONN]"],
  ["rediss URL with empty user", "rediss://:Zx9pQ2mN7v@cache.internal:6380", "[DB_CONN]"],
  ["SQLAlchemy dialect URL", 'url = "postgresql+psycopg2://u:p4ss@h/db"', 'url = "[DB_CONN]"'],
  ["credentials in an https URL", "git clone https://souvik:ghs_notarealtoken1234@git.example.com/x.git",
    "git clone https://souvik:[URL_CREDENTIALS]@git.example.com/x.git"],

  // Several secrets in one paste — none may be skipped
  ["DB URL plus AWS key", "DATABASE_URL=postgresql://admin:s3cretPw@db.internal:5432/app\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
    "DATABASE_URL=[DB_CONN]\nAWS_ACCESS_KEY_ID=[AWS_KEY]"],
  ["prefixed key plus unprefixed high-entropy value", "OPENAI=sk-proj-aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890ab\nSESSION_SIGNING=Zq8xW3vR7tY2uI9oP4aS6dF1gH5jK0lL",
    "OPENAI=[OPENAI_KEY]\nSESSION_SIGNING=[ENTROPY]"],

  // Passwords — any characters, 6+ long, value only
  ["short password", "password: hunter2", "password: [PASSWORD_HINT]"],
  ["password with symbols", "DB_PASSWORD=p@ss/w0rd?2024~xy", "DB_PASSWORD=[PASSWORD_HINT]"],
  ["password in JSON", '{"password":"Tr0ub4dor&3","user":"x"}', '{"password":"[PASSWORD_HINT]","user":"x"}'],
  ["password is ...", "my password is SuperSecret123!", "my password is [PASSWORD_HINT]"],

  // Validated PII
  ["Luhn-valid card", "card 4111 1111 1111 1111 exp 12/27", "card [CREDIT_CARD] exp 12/27"],
  ["Verhoeff-valid Aadhaar", "aadhaar 2341 2341 2346", "aadhaar [AADHAAR]"],
  ["OTP", "Your OTP is 482910", "Your OTP is [OTP_CODE]"],
  ["verification code", "verification code: 551203", "verification code: [OTP_CODE]"],

  // Entropy: KEY=value masks only the value; URL query params are split
  ["entropy value only", "SIGNING_KEY=Zq8xW3vR7tY2uI9oP4aS6dF1gH5jK0lL", "SIGNING_KEY=[ENTROPY]"],
  ["token in URL query", "GET https://api.x.com/v1?token=Zq8xW3vR7tY2uI9oP4aS6dF1gH5jK0lL&page=2",
    "GET https://api.x.com/v1?token=[ENTROPY]&page=2"],
  ["repeated secret masked every time", "a=Zq8xW3vR7tY2uI9oP4aS6dF1gH5jK0lL b=Zq8xW3vR7tY2uI9oP4aS6dF1gH5jK0lL",
    "a=[ENTROPY] b=[ENTROPY]"],
  ["specific key wins over generic KEY=value", "OPENAI_API_KEY=sk-proj-aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890ab", "OPENAI_API_KEY=[OPENAI_KEY]"],
  ["generic API key keeps the key name", "api_key: 'Zq8xW3vR7tY2uI9oP4aS'", "api_key: '[API_KEY_FORMAT]'"],
  ["bearer JWT keeps the JWT label", "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    "Authorization: Bearer [JWT]"],
  ["opaque bearer token keeps the Bearer keyword", "Authorization: Bearer Zq8xW3vR7tY2uI9oP4aS6dF1", "Authorization: Bearer [BEARER_TOKEN]"],
  ["40-hex value being assigned", "GH_OLD=3f786850e387550fdab836ed7e6dc881de23001b", "GH_OLD=[LONG_RANDOM_STRING]"],
];

// Inputs that must pass through untouched
const UNCHANGED = [
  ["12-digit order id (fails Verhoeff)", "Your order 234567891234 has shipped"],
  ["16-digit number failing Luhn", "ref 4111 2222 3333 4444"],
  ["exit code", "process failed with exit code 1234"],
  ["error code", "Error code: 50012 while syncing"],
  ["git commit SHA", "fixed in commit 3f786850e387550fdab836ed7e6dc881de23001b"],
  ["UUID request id", "request_id: 123e4567-e89b-12d3-a456-426614174000"],
  ["password from env call", 'password = os.getenv("DB_PASS")'],
  ["PWD env var", "PWD=/home/souvik/project"],
  ["password type annotation", "password: string;"],
  ["redacted password", "password: ********"],
  ["template password", "password: ${DB_PASSWORD}"],
  ["long file path", "see app/src/main/java/com/example/myapplication/MainActivity"],
  ["plain link", "docs at https://example.com/some/long/path/to/a/page?ref=abc"],
  ["ssh URL without password", "ssh://git@github.com:22/org/repo.git"],
  ["already masked text", "key [OPENAI_KEY_k3f9_0] and [DB_CONN_k3f9_1]"],
];

for (const [name, input, expected] of MASKED) {
  test(`masks: ${name}`, () => {
    assert.equal(d.scan(input).maskedText, expected);
  });
}

for (const [name, input] of UNCHANGED) {
  test(`ignores: ${name}`, () => {
    const r = d.scan(input);
    assert.equal(r.maskedText, input, `masked as ${r.labels.join(", ")}`);
  });
}

test("secrets at the end of a large (8 KB+) log are still masked", () => {
  const log = "INFO request ok id=42\n".repeat(400) +
    "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n" +
    "DATABASE_URL=postgresql://admin:s3cretPw@db.internal:5432/app";
  const r = d.scan(log);
  assert.ok(log.length > 8000);
  assert.equal(r.partial, false);
  assert.ok(!r.maskedText.includes("wJalrXUtnFEMI"));
  assert.ok(!r.maskedText.includes("s3cretPw"));
});

test("text above the full-scan limit is reported as partial but prefixed keys are still masked", () => {
  const big = "lorem ipsum dolor sit amet ".repeat(Math.ceil((d.DETECTOR_CONFIG.fullScanMaxLength + 10) / 27)) +
    " ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789";
  const r = d.scan(big);
  assert.equal(r.partial, true);
  assert.ok(r.maskedText.endsWith("[GITHUB_TOKEN]"));
});

test("hitting the match cap is reported as partial", () => {
  const many = Array.from({ length: d.DETECTOR_CONFIG.maxMatches + 5 }, () => "AKIAIOSFODNN7EXAMPLE").join(" ");
  assert.equal(d.scan(many).partial, true);
});

test("disabled patterns are skipped", () => {
  const compiled = d.compilePatterns(d.SHARED_PATTERNS, ["AWS_KEY"]);
  assert.equal(d.scan("key AKIAIOSFODNN7EXAMPLE", compiled).maskedText, "key AKIAIOSFODNN7EXAMPLE");
});

test("placeholders are unique per paste and round-trip through the helpers", () => {
  const ids = new Set(Array.from({ length: 200 }, () => d.newPasteId()));
  assert.ok(ids.size > 190, "paste ids should be random");

  const a = d.makePlaceholder("OPENAI_KEY", "k3f9", 0);
  const b = d.makePlaceholder("OPENAI_KEY", "x0zz", 0);
  assert.equal(a, "[OPENAI_KEY_k3f9_0]");
  assert.notEqual(a, b);
  assert.ok(d.PLACEHOLDER_TEST_RE.test(a));
  assert.equal(d.placeholderLabel(a), "OPENAI_KEY");
  assert.deepEqual([...d.findPlaceholders(`x ${a} y ${b} [NOT_A_PLACEHOLDER_0]`)], [a, b]);
});

test("Luhn and Verhoeff validators", () => {
  assert.equal(d.luhnValid("4111111111111111"), true);
  assert.equal(d.luhnValid("4111222233334444"), false);
  assert.equal(d.verhoeffValid("234123412346"), true);
  assert.equal(d.verhoeffValid("234567891234"), false);
});

test("every pattern stays fast on adversarial input (no catastrophic backtracking)", () => {
  const inputs = [
    "a".repeat(50000),
    "password: " + "x".repeat(50000),
    "postgres://" + ":".repeat(20000) + "@".repeat(20000),
    "https://" + "a:".repeat(20000),
    "1234 ".repeat(10000),
    "eyJ" + "a".repeat(30000) + ".eyJ" + "a".repeat(10000),
    "-----BEGIN PRIVATE KEY-----" + "A".repeat(50000),
  ];
  for (const input of inputs) {
    const start = performance.now();
    d.scan(input);
    const ms = performance.now() - start;
    assert.ok(ms < 500, `scan took ${ms.toFixed(0)} ms on ${JSON.stringify(input.slice(0, 30))}...`);
  }
});

test("full scan of 500 KB stays well under the paste-latency budget", () => {
  const line = "2026-10-11T10:00:00Z INFO req=123e4567-e89b-12d3-a456-426614174000 user=42 path=/api/v1/items/42\n";
  const text = line.repeat(Math.floor(d.DETECTOR_CONFIG.fullScanMaxLength / line.length));
  const start = performance.now();
  d.scan(text);
  assert.ok(performance.now() - start < 1000);
});
