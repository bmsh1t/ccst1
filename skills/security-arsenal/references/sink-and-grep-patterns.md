# Sink and Grep Pattern References

Load this file when source review or bundle review needs concrete sink names. These are candidate search patterns, not proof by themselves. A grep hit becomes useful only after dataflow from controlled input to sink and runtime evidence are shown.

## DOM / Client-Side Sources

```javascript
location.hash
location.search
location.href
document.referrer
window.name
document.URL
postMessage message.data
URLSearchParams
localStorage / sessionStorage values
```

## DOM / Client-Side Sinks

```javascript
innerHTML = source
outerHTML = source
document.write(source)
eval(source)
setTimeout(source, delay)      // string form
setInterval(source, delay)     // string form
new Function(source)
element.src = source           // javascript: or parser-specific URL handling
element.href = source
location.href = source
insertAdjacentHTML(..., source)
dangerouslySetInnerHTML
v-html
```

Evidence gate: source -> transform/sanitizer -> sink path, browser context, CSP/Trusted Types behavior, and a harmless execution/read-back proof.

## JavaScript / TypeScript Grep Patterns

```bash
grep -rn "__proto__\|constructor\[" --include="*.js" --include="*.ts" . | grep -v node_modules
grep -rn "postMessage\|addEventListener.*message" --include="*.js" --include="*.ts" . | grep -v node_modules
grep -rn "child_process\|execSync\|spawn(" --include="*.js" --include="*.ts" . | grep -v node_modules
grep -rn "innerHTML\|outerHTML\|insertAdjacentHTML\|dangerouslySetInner" --include="*.js" --include="*.ts" . | grep -v node_modules
```

## Python Grep Patterns

```bash
grep -rn "pickle\.loads\|yaml\.load\|eval(" --include="*.py" . | grep -v test
grep -rn "subprocess\|os\.system\|os\.popen" --include="*.py" . | grep -v test
grep -rn "__import__\|exec(" --include="*.py" .
```

## PHP Grep Patterns

```bash
grep -rn "unserialize\|eval(\|preg_replace.*e" --include="*.php" .
grep -rn "==.*password\|==.*token\|==.*hash" --include="*.php" .
grep -rn "\$_GET\|\$_POST\|\$_REQUEST" --include="*.php" . | grep "include\|require\|file_get"
```

## Go Grep Patterns

```bash
grep -rn "template\.HTML\|template\.JS\|template\.URL" --include="*.go" .
grep -rn "go func\|sync\.Mutex\|atomic\." --include="*.go" .
grep -rn "exec\.Command\|http\.Get\|url\.Parse" --include="*.go" .
```

## Ruby Grep Patterns

```bash
grep -rn "YAML\.load[^_]\|Marshal\.load\|eval(" --include="*.rb" .
grep -rn "attr_accessible\|permit(" --include="*.rb" .
```

## Rust Grep Patterns

```bash
grep -rn "\.unwrap()\|\.expect(" --include="*.rs" . | grep -v "test\|encode\|to_bytes\|serialize"
grep -rn "unsafe {" --include="*.rs" . -B5 | grep "read\|recv\|parse\|decode"
grep -rn "as u8\|as u16\|as u32\|as usize" --include="*.rs" . | grep -v "checked\|saturating\|wrapping"
```

## Server-Side RCE / Deserialization Sink Signals

Use these only for authorized source review. A match is a lead until reachable dataflow and runtime evidence exist.

| Family | Candidate sink |
|---|---|
| Command execution | `exec`, `spawn`, `system`, `popen`, shell wrappers, template helpers |
| Template trust override | raw HTML/template-safe wrappers, dynamic template names, custom filters |
| Deserialization | pickle, YAML unsafe load, Java/.NET/PHP/Ruby object loaders, ViewState handlers |
| File include/read | dynamic include/require, theme/locale/template path joins, archive extraction |
| SSRF/fetch | server-side HTTP clients receiving user-controlled URL or webhook target |
| XML parser | external entity enabled parser, SAML/XML/SVG/Office conversion path |

Dataflow gate: controlled input -> transform/parser -> sink -> observable output/timing/state. If the next step is high-impact, switch to an explicit script/action with raw evidence capture.

## Review Rule

Treat every match as a lead. Promote only after controlled input, reachable execution path, and raw evidence establish impact. If the next action is high-volume fuzzing or state change, switch to the relevant project script and `rules/red-lines.md` first.
