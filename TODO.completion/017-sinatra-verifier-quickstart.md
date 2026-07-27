# 017 — Sinatra verifier quickstart

**Category**: Audience
**Severity**: High (most Ruby users will be Sinatra / Rack developers)
**Effort**: Small (1 PR — documentation)

## Problem

The README is positioned for crypto framework adopters. But the
*typical* Ruby user wants: "I have a Sinatra app, someone gave me a
cert, I want to verify it". There's no doc for that.

**Why Sinatra, not Rails?** Sinatra is lighter, more universal, and
doesn't bury the crypto under framework boilerplate. The confium-ruby
audience leans toward microservices / API gateways rather than Rails
monoliths. A Rails quickstart may be added later as a *companion*, but
Sinatra is the default.

## Acceptance criteria

- [ ] `docs/quickstarts/sinatra-verifier.md` walks through:
  1. `bundle add confium sinatra puma`.
  2. A modular Sinatra app (`Sinatra::Base` subclass) exposing
     `POST /verify` that accepts a PEM cert in the request body.
  3. Parse with `Confium::PKI::Certificate.from_pem(...)`.
  4. Validate the cert's chain via `Confium::PKI::PathValidator`
     (tracked by [008](008-certificate-path-validation.md)).
  5. Rescue the typed Confium errors
     ([001](001-typed-error-hierarchy.md)) and return structured JSON.
  6. Render a JSON response with `valid:`, `errors:`,
     `subject_cn:`, `not_after:`.
- [ ] Uses idiomatic Sinatra patterns: `before` block for content-type,
     `error` blocks for typed errors, `halt` for early returns.
- [ ] The full example is ~60 lines of Ruby and runnable end-to-end.
- [ ] curl invocation example in the doc.

## Anti-patterns

- "Just use OpenSSL instead" — defeatist.
- Bundling TC signing into the verifier quickstart — keep the scope tight.
- Pulling in ActiveRecord / other Rails-isms — Sinatra-only deps.

## Approach

Write a fictional but realistic Sinatra app. The example uses
[`Confium::PKI::PathValidator`](008-certificate-path-validation.md) for
chain validation. Output ~120 lines of Markdown + ~60 lines of Ruby.

## Example shape

```ruby
# config.ru
require "./app"
run VerifyApp

# app.rb
require "sinatra/base"
require "confium"

class VerifyApp < Sinatra::Base
  before { content_type :json }

  post "/verify" do
    cert = Confium::PKI::Certificate.from_pem(request.body.read)
    result = Confium::PKI::PathValidator.validate(
      leaf: cert,
      root: Confium::PKI::Certificate.from_pem(File.read("ca.pem")),
    )
    {
      valid:      result.valid?,
      subject_cn: cert.subject_cn,
      not_after:  cert.not_after,
      errors:     result.errors,
    }.to_json
  rescue Confium::ParseError => e
    halt 400, { error: "parse_failed", details: e.details }.to_json
  rescue Confium::VerificationError => e
    halt 400, { error: "verification_failed", details: e.details }.to_json
  end
end
```

## Related

- [008-certificate-path-validation.md](008-certificate-path-validation.md) —
  the PathValidator is the centerpiece.
- [018-cnml-walkthrough.md](018-cnml-walkthrough.md) — domain-specific
  walkthrough that builds on this.
- [001-typed-error-hierarchy.md](001-typed-error-hierarchy.md) — the
  typed errors this quickstart rescues.
