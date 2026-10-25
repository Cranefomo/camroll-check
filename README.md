# camroll-check

find the screenshots in your camera roll that you forgot about.
seed phrases, card numbers, IBANs, passport photos, 2FA backup codes, API keys, passwords.

runs 100% on your machine. no uploads, no API keys. the report shows blurred thumbnails and masked values only, so even if you run it through an AI agent, the agent never sees the actual secret.

example run:

```
$ camroll-check \~/Pictures/iphone-export
\[camroll-check] ocr: apple-vision, heic: True, images: 8412
  found: seed\_phrase     high   IMG\_2291.PNG
  found: payment\_card    high   IMG\_0457.PNG
  found: recovery\_codes  high   IMG\_3310.PNG
  found: iban            medium IMG\_1180.PNG
  ...
\[camroll-check] scanned 8412, flagged 23, unreadable 0
report: camroll-report/report.html
```

## what it detects

|kind|how|severity|
|-|-|-|
|seed\_phrase|12+ words in a row from the BIP39 wordlist|high|
|payment\_card|13-19 digits that pass the Luhn check|high|
|id\_document|passport / ID machine-readable zone (the `P<UKR...<<` lines)|high|
|recovery\_codes|"backup codes" / "recovery codes" + a block of codes|high|
|private\_key, api keys|PEM private keys, `sk-`, `sk-ant-`, `ghp\_`, `AKIA`, `xox` tokens|high|
|iban|IBAN with a valid mod-97 checksum|medium|
|password|`password: ...` / `пароль: ...` written next to a label|medium|
|crypto\_address|BTC bech32 / ETH addresses|low|

checksums (Luhn, mod-97, BIP39) keep false positives low: a random 16-digit order number won't pass as a card.

## install

```
git clone https://github.com/Cranefomo/camroll-check \&\& cd camroll-check
pip install -e .
# Mac: use Apple Vision OCR (same engine as iPhone Live Text) + HEIC support
pip install -e ".\[mac]"
# Linux / Windows: needs tesseract installed (brew/apt/choco install tesseract)
```

## get your iPhone photos onto the computer

* **Mac:** plug the iPhone in, open **Image Capture**, pick the phone, select all, Import to a folder.
* **Windows:** plug in, allow access on the phone, open `This PC > Apple iPhone > Internal Storage > DCIM`, copy the folders.
* **iCloud Photos:** on a Mac, Photos > Settings > iCloud > Download Originals, then export.

then:

```
camroll-check ./iphone-export --since 2022-01-01
open camroll-report/report.html
```

## run it with Claude Code

this repo ships a skill in `.claude/skills/camroll-check/`. open the folder in Claude Code and say:

> check my iPhone export in \~/Pictures/iphone-export for screenshots with secrets

Claude runs the scan, reads only the masked summary, and walks you through cleaning up plus the iPhone privacy checklist in [CHECKLIST.md](CHECKLIST.md).

## after the scan

1. open each flagged original, decide if it should exist
2. delete it on the **phone** (not just in the export), then Photos > Albums > Recently Deleted > Delete All
3. if a seed phrase was in a screenshot that ever synced to a cloud: move the funds to a new wallet
4. if a card or IBAN was there: you're mostly fine, but watch statements. if the CVV was visible, consider a reissue
5. API keys and tokens: rotate them, they're the easiest to abuse
6. delete the export folder and the report when done

## limits

* it only sees text. a photo of a card at an angle may not OCR cleanly
* handwritten seed phrases usually won't be detected
* tesseract uses English by default. for Cyrillic install the `ukr` language pack and run with `CAMROLL\_LANG=eng+ukr`. Apple Vision on a Mac doesn't need this

MIT license. BIP39 wordlist from [trezor/python-mnemonic](https://github.com/trezor/python-mnemonic) (MIT).

