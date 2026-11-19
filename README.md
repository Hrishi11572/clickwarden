![ClickWarden](assets/logo.png)

# ClickWarden

ClickWarden has two parts that work together:

| What you asked for | What handles it |
|---|---|
| 1. Check a link **before** it opens | **Browser extension**: checks a link when you hover over it, holds your click until the check is done, and acts as a safety net for links opened from other apps |
| 2. Spot strange downloads while you browse | **Browser extension**: catches drive-by downloads, disguised file names, page-built ("smuggled") files and bursts of automatic downloads, then pauses the download and asks you |
| 3. Check whether a downloaded file is known malware | **Extension + desktop watcher**: both hash the file and look it up in MalwareBazaar and VirusTotal; the watcher can also use ClamAV and moves malware into quarantine |

The watcher is there because a browser extension can't read files on your disk. The extension can only download the file a second time and hash that copy, which works most of the time. The watcher reads the actual saved file, so it also covers downloads from other apps (WhatsApp, Telegram, torrent clients and so on).

---

## 1. Get the free API keys (about 10 minutes)

ClickWarden runs without keys, but then it only has its offline checks. Each key adds a source:

| Key | Covers | Where |
|---|---|---|
| **Google Safe Browsing** | Phishing and malware websites | Google Cloud Console → create a project → enable **Safe Browsing API** → Credentials → *Create API key* |
| **abuse.ch Auth-Key** | URLhaus (malware download links) and MalwareBazaar (known malware files) | Sign up at **auth.abuse.ch**. One key covers both services |
| **VirusTotal** | Results from 70+ antivirus engines | Free account at **virustotal.com** → profile → *API key*. Free tier: 4 lookups/min, 500/day, personal use only |

## 2. Install the browser extension (Chrome, Edge, Brave, Arc, Opera)

1. Unzip the download and keep the `extension` folder somewhere permanent. The browser loads the extension from that folder.
2. Open `chrome://extensions` (in Edge: `edge://extensions`).
3. Turn on **Developer mode** (top-right toggle).
4. Click **Load unpacked** and select the `extension` folder.
5. The Settings page opens. Paste your keys, click **Test keys** (each should say *OK*), then click **Save**.
6. Pin the 🛡️ icon to your toolbar.

**Try it out**
- Google provides a safe test page that is always flagged: `http://malware.testing.google.test/testing/malware/`. Paste it into the address bar and ClickWarden should block it.
- Right-click any link → **Check this link with ClickWarden** to run every source, including VirusTotal.
- The popup shows the current page's verdict, has a box for checking a pasted link, and lists your recent downloads.

## 3. Run the desktop watcher (Windows, macOS, Linux)

You need Python 3.9 or later. Nothing else is required.

```bash
cd watcher
pip install -r requirements.txt               # optional: instant detection + nicer notifications
python clickwarden_watcher.py setup            # paste your abuse.ch and VirusTotal keys
python clickwarden_watcher.py watch            # watches your Downloads folder
```

Other commands:

```bash
python clickwarden_watcher.py scan ~/Downloads        # scan existing files once
python clickwarden_watcher.py watch --dir "D:\Dl"     # watch a different folder
python clickwarden_watcher.py watch --no-quarantine   # warn only, don't move files
python clickwarden_watcher.py quarantine              # list quarantined files
python clickwarden_watcher.py quarantine --restore <name>
```

When a file is known malware (a MalwareBazaar match, 3 or more VirusTotal engines, or a ClamAV hit), the watcher moves it to `~/.clickwarden/quarantine/`, makes it read-only and shows a desktop notification. Everything it does is logged to `~/.clickwarden/watcher.log`.

**Start the watcher automatically at login**
- **Windows:** press Win+R, type `shell:startup`, and in that folder create `clickwarden.bat` containing
  `start "" pythonw "C:\path\to\watcher\clickwarden_watcher.py" watch`
- **macOS:** System Settings → General → Login Items, or create a launchd agent.
- **Linux:** add a `~/.config/autostart/clickwarden.desktop` entry, or create a systemd `--user` service.

---

## How the checks work

**Links** (verdicts are cached for 30 minutes)
- *Blocklists:* Google Safe Browsing and URLhaus are checked on every page load. VirusTotal is used for manual checks, plus every page load if you switch that on.
- *Offline phishing checks:* raw IP addresses, punycode look-alike domains, the `user@host` trick, brand names on domains the brand doesn't own (`paypal-secure-login.xyz`), look-alike spellings (`amaz0n`), scam words in the domain (`sbi-kyc-update`), cheap scam-heavy TLDs, odd ports and link shorteners.
- **Blocklisted** pages are always blocked. Pages that are only **suspicious** get a warning when you click them, and are blocked outright only if you turn that on in Settings.
- Only links to *other* sites are held when clicked, so navigating within a site isn't slowed down.

**Download behaviour** (a score of 50 or more pauses the download and opens an alert; 25–49 shows a notification)
- The download started with no click or keypress from you in the previous 5 seconds (drive-by download)
- The file type can run code: `.exe .msi .scr .bat .ps1 .vbs .js .hta .jar .lnk .iso .apk .dmg …`
- Double extensions (`invoice.pdf.exe`), hidden right-to-left characters, or extensions pushed out of view with spaces
- The server says the file is a program but the name says `.jpg` or `.pdf`
- The file was built inside the page (`blob:`/`data:` URLs, a technique called HTML smuggling)
- The file is served from an unrelated site, or the site started 3 or more downloads in 10 seconds
- The download link itself is on a blocklist

**Files**
- A SHA-256 hash is looked up in MalwareBazaar and VirusTotal. The file itself is never uploaded.
- "Unknown" means no database has seen that exact file. That's normal for most legitimate files, but it doesn't prove the file is safe.

## Honest limitations

- A hash lookup only catches **known** malware. New or one-off samples can return "unknown". Keep Windows Defender (or your OS's antivirus) on, because ClickWarden adds to it and doesn't replace it.
- The extension re-downloads files to hash them. This doesn't work for one-time links, and the second copy can occasionally differ from the first; the alert says when that happens. The watcher has neither problem.
- Chrome extensions can't hold a page load completely. For links opened from outside the browser, a dangerous page could start loading for a split second before ClickWarden replaces it with the warning. Clicks inside web pages are checked before anything loads.
- The free VirusTotal tier allows 4 lookups per minute, so the watcher waits about 15 seconds between VirusTotal calls.
- Your API keys are stored on your own computer only: in the browser's extension storage, and in `~/.clickwarden/config.json` (readable only by you on macOS and Linux).
