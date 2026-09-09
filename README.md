# @guardbee/mcp-dependency-auditor

[![npm version](https://img.shields.io/npm/v/@guardbee/mcp-dependency-auditor.svg)](https://www.npmjs.com/package/@guardbee/mcp-dependency-auditor)
[![npm downloads](https://img.shields.io/npm/dm/@guardbee/mcp-dependency-auditor.svg)](https://www.npmjs.com/package/@guardbee/mcp-dependency-auditor)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

npm, pip ve diğer paket yöneticilerinin bağımlılıklarını bilinen CVE'ler için [OSV](https://osv.dev) veritabanına karşı tarayan MCP sunucusu. Claude'a doğrudan projenizin güvenlik durumunu sorabilirsiniz.

---

## Özellikler

- **OSV API Entegrasyonu** — Google'ın açık kaynak güvenlik açığı veri tabanı (ücretsiz, kimlik doğrulaması gerektirmez)
- **npm Desteği** — `package.json` ve `package-lock.json` (v1/v2/v3) okunur; kilitli sürümler tercih edilir
- **pip Desteği** — `requirements.txt`, `requirements/base.txt`, `requirements/prod.txt` ve `pyproject.toml`
- **Severity Skorlaması** — CVSS puanına veya metin buluşsal yöntemine göre Critical / High / Medium / Low
- **Düzeltme Sürümü** — Mevcut olduğunda `upgrade to X@Y.Z.Z` önerisi
- **CVE Bağlantıları** — NVD veya osv.dev'e doğrudan link
- **20 Unit Test** — %100 geçen test paketi

---

## Hızlı Başlangıç

```bash
npm install -g @guardbee/mcp-dependency-auditor
```

`claude_desktop_config.json` dosyasına ekleyin:

```json
{
  "mcpServers": {
    "guardbee-dependency-auditor": {
      "command": "npx",
      "args": ["-y", "@guardbee/mcp-dependency-auditor"]
    }
  }
}
```

---

## MCP Tools

| Tool | Açıklama |
|------|----------|
| `audit_npm` | `package.json` / `package-lock.json` içindeki npm bağımlılıklarını denetler |
| `audit_pip` | `requirements.txt` / `pyproject.toml` içindeki Python bağımlılıklarını denetler |
| `audit_package` | Tek bir paketi ad, sürüm ve ekosisteme göre denetler |
| `audit_directory` | Desteklenen tüm manifest dosyalarını otomatik tespit ederek denetler |

### Örnek Kullanım

Claude'a şunu sorabilirsiniz:

> "Bu projemin npm bağımlılıklarını denetle: `/Users/me/my-app`"

> "lodash 4.17.20 sürümünde CVE var mı?"

> "Python projemi tara: `/Users/me/django-app`"

### Örnek Çıktı

```
⚠️  Found 3 vulnerabilities in 2/142 npm packages (1243ms)
   Critical: 1  High: 1  Medium: 1  Low: 0  Unknown: 0

[CRITICAL] lodash@4.17.20
  ID      : GHSA-35jh-r3h4-6jhm (CVE-2021-23337)
  Summary : Command injection via template
  Fix     : upgrade to lodash@4.17.21
  Details : https://nvd.nist.gov/vuln/detail/CVE-2021-23337
```

---

## Desteklenen Ekosistemler

`audit_package` tool'u şu ekosistemler için doğrudan sorgu yapabilir:

| Ekosistem | Parametre |
|-----------|-----------|
| npm | `npm` |
| Python | `PyPI` |
| Rust | `crates.io` |
| Java | `Maven` |
| Go | `Go` |
| Ruby | `RubyGems` |

---

## CLI — CI/CD Entegrasyonu

MCP server moduna ek olarak doğrudan CLI olarak da kullanılabilir:

```bash
# Dizindeki tüm bağımlılıkları denetle (npm + pip otomatik tespit)
npx @guardbee/mcp-dependency-auditor audit ./my-project

# Sadece npm
npx @guardbee/mcp-dependency-auditor audit-npm . --fail-on=critical

# Sadece pip
npx @guardbee/mcp-dependency-auditor audit-pip . --fail-on=high

# Tek paket
npx @guardbee/mcp-dependency-auditor audit-pkg lodash 4.17.20 npm

# JSON çıktı
npx @guardbee/mcp-dependency-auditor audit . --format=json
```

**Exit kodları:** `0` = temiz · `1` = threshold üstü bulgu · `2` = hata

### GitHub Actions

```yaml
name: Dependency Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: npm ci
      - name: Audit dependencies
        run: npx @guardbee/mcp-dependency-auditor audit . --fail-on=high
```

### GitLab CI

```yaml
dependency-audit:
  image: node:20
  script:
    - npx @guardbee/mcp-dependency-auditor audit . --fail-on=high
  only:
    - merge_requests
    - main
```

### Pre-commit Hook

```bash
# .git/hooks/pre-push
npx @guardbee/mcp-dependency-auditor audit . --fail-on=critical || exit 1
```

---

## Geliştirme

```bash
npm install
npm test          # 20 unit test
npm run build     # TypeScript derleme
```

---

## Lisans

MIT — [GuardBee](https://guardbee.ai)
