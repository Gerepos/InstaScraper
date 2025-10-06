# CHANGELOG

This file documents changes made locally to `release/Scraper.py` compared to the original upstream repository https://github.com/supmanyu/InstaScraper.

All changes were implemented to make the scraper more robust, localizable and to improve correctness when dealing with viewer services and proxies.

## Summary (high level)
- Add interactive per-user language selection (German/English) and localized output.
- Replace fragile theinstaprofile Cloudflare logic by:
  - Primary lookup: Instagram profile page
  - Fallbacks: viewer services (Inflact, Stealthgram, Instapv, PathSocial)
- Make optional dependencies safe (mechanize / proxylist may be missing and won't crash the script).
- Add a simple proxy-file loader and proxy rotation per-session.
- Optional Playwright rendering (`--playwright`) to fetch JS-rendered pages.
- More robust error handling for network errors, SSL errors and HTTP status codes.
- Discard emails that are clearly from the viewer site's domain (to avoid writing viewer-provided contact emails to `Output.csv`).
- Improve step-by-step output formatting: numbered steps are localized and each numbered step is followed by a blank line for readability.
- Add human-friendly HTTP status explanations (e.g. 403 -> "zugriff verweigert / blockiert").

## File-level changes
- `release/Scraper.py` — major refactor and enhancements:
  - New helper functions:
    - `ask_language_choice(username)` - interactive prompt for language per user.
    - `tr(msg_key, lang, **kwargs)` - translation helper for a small set of messages.
    - `find_emails_in_text(text)` - regex-based email finder (existing but hardened).
    - `fetch_with_playwright(url, timeout)` - Playwright-based fetch helper (optional).
    - `load_proxies_from_file(path)` and `choose_proxy(list)` - simple proxy loader and chooser.
    - `is_email_from_same_domain(email, url)` - normalized domain comparison to detect viewer-supplied emails.
    - `explain_status(status, lang)` and `site_status_message(url, status, lang)` - readable status messages.
  - `query_viewers(username, session, proxy)` was updated to:
    - Use simple GET requests to known viewer URLs.
    - On HTTP 200, parse the HTML and check for emails.
    - Discard emails that match the viewer's domain (append a results entry stating it was discarded and continue searching).
  - `init_scraper()` was refactored to:
    - Prompt for language per user and format outputs accordingly.
    - Use the new step collection (`steps`) and print numbered, localized steps with blank lines.
    - Write `Output.csv`, but skip viewer-domain emails.

## Behavioral changes / rationale
- Previously, some viewer services often injected their own contact addresses (e.g. `hello@pathsocial.com`). These are not the target profile's email. To avoid false positives, the script now removes emails whose domain matches the viewer domain.

- Many viewer pages are JS-driven; the `--playwright` option helps to render those pages and increases the chance of extracting data.

- Many external services will return 403/404/429 or block scripts; the script now explicitly records these codes and adds an explanatory note so the user can quickly identify the failure mode.

## How to test
1. Run a single user test:

```bash
python release/Scraper.py -u some_username
```

2. Try with Playwright:

```bash
pip install playwright
python -m playwright install
python release/Scraper.py -u some_username --playwright
```

3. Provide a `-X /path/to/proxies.txt` file to test proxy usage. The proxies file must have one proxy URL per line.

## Additional recommendations
- If you rely on `cfscrape` anywhere else, pin `urllib3<2` in `requirements.txt` to avoid import errors caused by urllib3 v2 API changes.
- Fix WSL system CA stores if you encounter `requests.exceptions.SSLError` repeatedly (install `ca-certificates`, or use `certifi` as a temporary measure).

## Changelog (short timeline)
- Add localized interactive language prompt and `tr()` translations.
- Implement Playwright fetch helper and `--playwright` CLI option.
- Replace `theinstaprofile` flow with viewer fallbacks.
- Make mechanize/proxylist optional; add fallback proxy file loader.
- Implement `is_email_from_same_domain` and filter viewer-supplied emails.
- Improve step output formatting (blank lines, numbered and localized lines).
- Add readable HTTP status explanations.