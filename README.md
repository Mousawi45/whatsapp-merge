# Merge your old WhatsApp chats into your current phone (free, no data loss)

*Last updated 18 November 2026*

You can merge an old phone's WhatsApp history into the WhatsApp on your current phone and keep both, for free, using your own devices and the official WhatsApp app. This guide shows how, step by step. The tool, [`wa_merge.py`](wa_merge.py), is in this repository.

WhatsApp has no merge button. Restoring a Google backup, "Transfer chats" between Android phones, and the official iPhone-to-Android transfer all **replace** the history on the target phone. So if you started fresh on a new phone and later revived the old one, WhatsApp makes you choose: old chats or new chats. This guide gets you both.

**How it works:** you make a local, encrypted backup on each phone, unlock both with their 64-digit keys, copy the old history into the current one, lock the result again, and restore it on your current phone. Messages, photos, videos, documents, voice notes, replies, reactions, polls, calls, contact cards and locations come across. Chats with the same person or group are joined into one.

**It's proven on a real phone.** In November 2026, Method A merged 4.2 million messages (2014 to 2026, 12,905 chats, about 60,000 media files) from a Galaxy S23 Ultra into a Galaxy S26 Ultra that already had months of new chats. WhatsApp restored the merged backup, and old and new history showed up together.

**Honest limits:**

- It's unofficial. WhatsApp and Meta don't support it, and a future WhatsApp update could change the backup format and stop it working.
- Both backups must be end-to-end encrypted with a **64-digit key**. Password-protected or Google-only backups can't be opened.
- Method A (Android to Android, on the phone) was tested end to end. Methods C and D (iPhone) are workflows documented by the open-source tool **wakit**, but this guide hasn't tested them on a phone.
- You need a few hours, plenty of free space, and the patience to follow every step. Keep untouched copies of your backups until the end.

## Contents

- [Which method fits you](#which-method-fits-you)
- [Before you start](#before-you-start)
- [Step 1: make the backups (everyone)](#step-1-make-the-backups-everyone)
- [Method A: Android to Android on the phone itself](#method-a-android-to-android-on-the-phone-itself)
- [Method B: Android to Android with a computer](#method-b-android-to-android-with-a-computer)
- [Method C: old iPhone to current Android](#method-c-old-iphone-to-current-android)
- [Method D: old Android to current iPhone](#method-d-old-android-to-current-iphone)
- [Restore on Android (Methods A, B and C)](#restore-on-android-methods-a-b-and-c)
- [Troubleshooting and FAQ](#troubleshooting-and-faq)
- [Fix search after an earlier merge](#fix-search-after-an-earlier-merge)
- [Cleanup afterwards](#cleanup-afterwards)
- [Credits, licence and disclaimer](#credits-licence-and-disclaimer)

## Which method fits you

Pick the row that matches your phones. Everyone does **Step 1** (the backups) first. A, B and C then finish with the same **Restore on Android** section.

| Your situation | Method | What you need | Tested here |
| --- | --- | --- | --- |
| Old Android → current Android, no computer | **A: on the phone itself** (Termux + wa_merge.py) | Your current Android phone, about 20 GB free | Yes, end to end |
| Old Android → current Android, with a computer | **B: on a computer** (wa_merge.py or wakit) | Windows, Mac or Linux | Partly: same merge logic as A; the computer run was tested on Linux |
| Old iPhone → current Android | **C: wakit from-ios** | A computer that can make an unencrypted iPhone backup | No (wakit's documented workflow) |
| Old Android → current iPhone | **D: wakit to-ios** | A Mac is best; the whole iPhone is restored from a backup | No (wakit's documented workflow) |

**Only have "Export chat" files from the old phone?** wakit can also turn exported .zip or .txt chats back into real history on Android, with `wakit import`. See [wakit's README](https://github.com/menaxmaged/wakit), workflow 1.

**Starting on a brand-new phone with nothing on it yet?** You don't need any of this. Use WhatsApp's own transfer or restore during setup.

## Before you start

You need these five things, or the merge can't work:

1. **The same phone number** on both phones' WhatsApp. Backups are tied to the number.
2. **A backup from each phone, end-to-end encrypted with a 64-digit key.** Each phone gets its own key. Password-protected backups won't work, because the key behind the password stays on WhatsApp's servers.
3. **The old phone must be able to open WhatsApp**, so it can make that backup. If it's dead but you have a Google backup, restore that backup on any working Android phone and make the 64-digit backup there.
4. **Free space on the phone or computer doing the merge:** about 4.5 times the size of the old backup file. In the test, a 3.9 GB backup needed about 18 GB.
5. **2–3 hours** with the charger plugged in. On a Galaxy S26 Ultra, the tool itself took about 20 minutes for 4.2 million messages; the rest is copying and restoring.

**Safety rules for the whole process:**

- **Keep an untouched copy of both backup files and both keys** until you've checked the result for a few days. The current phone's untouched backup is your undo button.
- **Never uninstall WhatsApp before moving the WhatsApp folder out** of `Android/media/com.whatsapp`. Uninstalling deletes that folder, including all the media in it.
- **Never tap "Replace"** when moving or copying folders into the WhatsApp folder. It can delete the photos already there.
- **From the current phone's final backup until the restore, keep that phone offline** (airplane mode, Wi-Fi off) and don't open WhatsApp. Anything sent to you meanwhile waits on WhatsApp's servers and arrives after the restore. Messages that reached the phone after its final backup would be lost.
- **Log out of linked devices** (WhatsApp Web, desktop) before the final backup, so you don't reply from them during the process.

## Step 1: make the backups (everyone)

You end this step with the old phone's backup file and media on your current phone, a 64-digit key for each phone, and an untouched safety copy of the current phone's backup. iPhone users: do the Android parts of this step on your Android phone, then go to Method C or D.

**On the current phone (the one you keep)**

1. WhatsApp → Settings → Chats → Chat backup → **End-to-end encrypted backup** → turn it on and choose **Use 64-digit encryption key instead**. Save the key in two places, such as a notes app and a photo. Label it **current phone key**.
2. Tap **Back up**.
3. Safety copy: in My Files, copy `Android/media/com.whatsapp/WhatsApp/Databases/msgstore.db.crypt15` somewhere outside the Android folder, or to a computer or cloud drive.

**On the old phone**

4. Open WhatsApp. If it asks you to verify your number, verifying moves your account to the old phone for now. Your current phone keeps its chats and asks you to verify again later. In the test, all its chats were still there after re-verifying, and your safety copy covers you anyway.
5. Set up end-to-end encrypted backup with a **64-digit key** here too. It's a different key; label it **old phone key**. Then tap **Back up**.
6. Copy two things to the current phone:
    - the backup file `Android/media/com.whatsapp/WhatsApp/Databases/msgstore.db.crypt15`. Older phones keep it in `WhatsApp/Databases/` instead.
    - the **Media** folder from `Android/media/com.whatsapp/WhatsApp/`, which holds your photos, videos, documents and voice notes.
7. On the current phone, put them in Internal storage as **WA old backup/msgstore.db.crypt15** and **WA-old-media/Media**.

**Copying tips**

- A USB cable to a computer works if the old phone's port transfers data. If it only charges, use Quick Share or Nearby Share.
- Tens of thousands of media files transfer much faster as **one zip**. In My Files, select the Media folder → **Compress**, send the zip, then extract it on the current phone. You need free space for the zip on both phones.
- After copying, compare the file counts on both phones (long-press the folder → **Details**).

**Back on the current phone**

8. Open WhatsApp and verify your number again if asked. Check that your chats are there.

## Method A: Android to Android on the phone itself

This runs entirely on your current phone, in a free app called Termux, with the script [`wa_merge.py`](wa_merge.py). It's built on wakit's merge code, with changes for phones:

- It decrypts and encrypts in small pieces, so it uses about 2.5 GB of memory for 4 million messages, against over 5 GB for wakit on a computer.
- It shows progress the whole time.
- It also copies details wakit 0.3.0 leaves out: contact cards, shared locations, call bubbles, read info, group invites and more.
- It completes and rebuilds WhatsApp's search index, so messages from both phones can be found with search.
- It never changes your original backup files, checks everything before and after, and can pick up where it stopped.

**Set up Termux (once, with internet)**

1. Install **Termux** from F-Droid: open [f-droid.org/packages/com.termux](https://f-droid.org/packages/com.termux/) and tap **Download APK** under the version marked **suggested**. Don't use the Play Store version; its developers say it's outdated.
2. Open Termux and type these one at a time. Tap **Allow** if asked, and press Enter at any other question. The last line downloads the script from this repository.

```
termux-setup-storage
pkg update -y
pkg install -y python python-cryptography curl
pip install wakit==0.3.0
curl -LO https://raw.githubusercontent.com/Mousawi45/whatsapp-merge/main/wa_merge.py
```

3. Go to Settings → Apps → **Termux** → Battery and choose **Unrestricted**, so Android doesn't stop it.

**Put the old backup in place**

4. In My Files, make a folder called **WA old backup** in Internal storage and put the old phone's **msgstore.db.crypt15** in it. If you keep it somewhere else, add `--old "<path to the file>"` to the command below.

**Optional head start:** run the command in step 7 now. It unlocks and checks the old backup, the slowest part, which doesn't touch WhatsApp. When it asks *"Is this backup fresh and is the phone offline?"*, type **no**. It stops there and remembers its progress.

**Run the merge**

5. In WhatsApp on the current phone: log out of all **Linked devices**, turn on **airplane mode** with Wi-Fi off, then Settings → Chats → Chat backup → **Back up**. A failed Google Drive upload is fine; the local file is what matters. Close WhatsApp and don't open it again until the restore.
6. Plug in the charger. In Device care → Memory, tap **Clean now** to free memory. Don't tap it while the tool runs.
7. In Termux, type:

```
python wa_merge.py
```

8. Paste the **old phone's key** when asked; nothing shows on screen, which is normal. Type **yes** to the offline question, then paste the **current phone's key**.
9. Read the **MERGE REPORT**. It shows messages copied, chats added or combined, and a **not copied** list of minor details it skipped on purpose. Type **yes** to make the restorable file.
10. When it asks to delete the unlocked copies, type **no** for now. They save time if you need a second try. Uninstalling Termux at the end deletes them.

When it says **ALL DONE**, your **WA work** folder holds:

- **msgstore.db.crypt15**: the merged backup to restore
- **current-original.crypt15**: an untouched copy of the current phone's backup, which is your undo

Now go to [Restore on Android](#restore-on-android-methods-a-b-and-c).

**If you need to run it again** (say you used WhatsApp in between), make a new backup in airplane mode and run `python wa_merge.py --redo-merge`. The old backup isn't unlocked again. Run `python wa_merge.py --help` to see all options.

## Method B: Android to Android with a computer

The same merge can run on Windows, Mac or Linux, either with **wa_merge.py** (recommended: low memory, progress, extra details) or with **wakit's** own commands. Either way, the result goes back to the phone for the restore.

**Get the files onto the computer**

1. On the current phone, follow the offline rules: log out of linked devices, turn on airplane mode, tap **Back up**, and don't open WhatsApp again.
2. Copy both backups to the computer, for example into folders called `old` and `current`. Each is called `msgstore.db.crypt15`.
3. Install Python 3.9 or newer from [python.org](https://www.python.org/downloads/). On Windows, tick **Add python.exe to PATH** during setup.
4. Download [`wa_merge.py`](wa_merge.py) from this repository (open it, then use the download button) into the same folder.

**Option 1: wa_merge.py on the computer**

```
pip install wakit==0.3.0 cryptography
python wa_merge.py --old old/msgstore.db.crypt15 --current current/msgstore.db.crypt15 --out merged --work work
```

It uses about 2.5 GB of memory for 4 million messages, shows progress, and picks up where it stopped if the computer restarts. On a computer it was tested on Linux; Windows and Mac should work the same way but weren't tested. It asks for both keys, shows a report, and writes `merged/msgstore.db.crypt15` plus `merged/current-original.crypt15` (your undo).

**Option 2: wakit's own commands**

```
pip install "wakit[crypt]"
wakit crypt decrypt --in old/msgstore.db.crypt15 --key "<OLD key>" --out old.db
wakit crypt decrypt --in current/msgstore.db.crypt15 --key "<CURRENT key>" --out current.db
wakit doctor --path old.db
wakit merge --old old.db --new current.db
wakit merge --old old.db --new current.db --apply
wakit crypt encrypt --in current.db --like current/msgstore.db.crypt15 --key "<CURRENT key>" --out merged/msgstore.db.crypt15
```

The first `merge` is a dry run that only reports; `--apply` writes. If `doctor` says the old database's search index (`message_ftsv2`) is damaged, repair it before merging:

```
python -c "import sqlite3; c=sqlite3.connect('old.db'); c.execute(\"INSERT INTO message_ftsv2(message_ftsv2) VALUES('rebuild')\"); c.commit()"
```

**Lessons from the test run with wakit on a laptop:**

- wakit prints **nothing** until the merge ends. With millions of messages that can take hours and look frozen.
- It used **over 5 GB of memory** for 4.2 million messages. Close other apps, and use a computer with 16 GB of RAM if you can.
- **Pause Windows Update** first. In the test, an automatic restart killed a merge that had been running for hours.
- wakit 0.3.0 doesn't copy contact cards, shared locations, call bubbles or read info. wa_merge.py does.

Copy `merged/msgstore.db.crypt15` to a **WA work** folder in the phone's Internal storage, then go to [Restore on Android](#restore-on-android-methods-a-b-and-c). When everything works, delete the unlocked `.db` files on the computer (and the `work` folder). They're readable copies of all your chats, so also delete the `.bak-` copies wakit makes next to them and anything named `old.db` in your temp folder.

## Method C: old iPhone to current Android

wakit's `from-ios` command adds an iPhone's WhatsApp chats into an Android database, joining chats with the same person or group. You need a computer. This is wakit's documented workflow, and this guide hasn't tested it on a phone.

**What comes across** (per wakit): text, links, photos with captions, videos, GIFs, voice notes and audio, stickers, documents, contact cards, locations (as a maps link), deleted-message markers and group senders. **What doesn't:** system notices, calls, polls, reactions and reply quotes.

1. **Back up the iPhone to the computer, unencrypted.** On a Mac use Finder; on Windows use Apple Devices or iTunes. Untick **Encrypt local backup**. WhatsApp's data is inside this backup.
2. **On the Android phone**, do the current-phone part of Step 1 and follow the offline rules. Copy its `msgstore.db.crypt15` to the computer.
3. **Install wakit** on the computer: `pip install "wakit[crypt]"`.
4. **Unlock, add the iPhone chats, lock again:**

```
wakit crypt decrypt --in current/msgstore.db.crypt15 --key "<ANDROID key>" --out android.db
wakit from-ios --db android.db --backup "<iPhone backup folder>"
wakit from-ios --db android.db --backup "<iPhone backup folder>" --media-out ios-media --apply
wakit crypt encrypt --in android.db --like current/msgstore.db.crypt15 --key "<ANDROID key>" --out merged/msgstore.db.crypt15
```

The backup folder is the one holding `Manifest.db`. On Windows it's usually in `%USERPROFILE%\Apple\MobileSync\Backup` (older iTunes: `%APPDATA%\Apple Computer\MobileSync\Backup`); on a Mac it's in `~/Library/Application Support/MobileSync/Backup`. The first `from-ios` is a dry run that only reports.

5. **Copy the results to the phone:** `merged/msgstore.db.crypt15` into a **WA work** folder, and the media from `ios-media` into a **WA-old-media** folder, so you have `WA-old-media/Media/...`.
6. Go to [Restore on Android](#restore-on-android-methods-a-b-and-c).

If this is a brand-new Android phone with no chats to keep, WhatsApp's own iPhone-to-Android transfer during setup is simpler.

## Method D: old Android to current iPhone

wakit's `to-ios` command adds an Android phone's chats into a copy of your iPhone's backup, which you then restore to the iPhone. **Restoring replaces everything on the iPhone with that backup**, not just WhatsApp. That makes this the riskiest method, so read wakit's own instructions in full before trying it. This guide hasn't tested it.

**What comes across** (per wakit): text, photos, videos, GIFs, voice notes, stickers, documents, contact cards, locations, deleted-message markers, stars, group senders and reply quotes. **What doesn't:** system notices, calls, polls and reactions.

The outline:

1. Unlock the Android backup on a computer with `wakit crypt decrypt` (Method B, option 2), and copy the Android phone's WhatsApp **Media** folder to the computer.
2. Make a **fresh, full, unencrypted** backup of the iPhone, and work on a **copy** of it.
3. Run `wakit to-ios --db android.db --backup <copy of the iPhone backup> --media <copied WhatsApp folder>`, first as a dry run, then with `--apply`.
4. Restore the edited copy to the iPhone.

**wakit's warnings:**

- A Mac is best supported; it makes the photo thumbnails with macOS tools.
- Use a backup made **just before**, because anything added to the iPhone after it is lost.
- **Never** restore a backup cut down to WhatsApp only.
- Turn off **Find My**, keep the iPhone **unlocked** until it reboots, and when WhatsApp opens, **skip** any iCloud restore it offers.

Full commands and details: [wakit's README](https://github.com/menaxmaged/wakit), workflow 3.

## Restore on Android (Methods A, B and C)

You move WhatsApp's folder out of harm's way, swap in the merged backup, add the old media, reinstall WhatsApp, and restore. Keep the phone offline until step 5. You need **WA work/msgstore.db.crypt15** (the merged file) and **WA-old-media/Media** in Internal storage. Use the My Files app.

**Prepare the folder**

1. Open **Android → media → com.whatsapp** and **move** (not copy) the **WhatsApp** folder into **WA work**. Uninstalling WhatsApp deletes everything left in com.whatsapp.
2. Open **WA work → WhatsApp → Databases**. Make a folder **WA work/old backups** and move **every** file whose name starts with `msgstore` into it. That includes dated ones and `msgstore-increment…` files, which WhatsApp might otherwise apply on top. Then move the merged **WA work/msgstore.db.crypt15** into **Databases**. It should be the only msgstore file there.
3. Add the old media **without overwriting anything**. Don't drag folders onto same-named folders in My Files, because it can offer **Replace**. In Termux, type this as one line instead:

```
cp -rn --preserve=timestamps ~/storage/shared/WA-old-media/Media/. ~/storage/shared/"WA work"/WhatsApp/Media/
```

It shows nothing while copying. To check, run the line below. The second number should be the first plus the current phone's own media files.

```
find ~/storage/shared/WA-old-media/Media -type f | wc -l; find ~/storage/shared/"WA work"/WhatsApp/Media -type f | wc -l
```

No Termux? Copy the phone's **WA work/WhatsApp/Media** folder to a computer, drop the old media folders into it, choose **Skip** for files that already exist, and copy it back.

**Reinstall WhatsApp**

4. Settings → Apps → WhatsApp → **Uninstall**. Leave **Keep app data** unticked, or WhatsApp comes back with the old chats and never offers the restore.
5. Turn airplane mode off; that's safe now, because WhatsApp is gone. Install WhatsApp from the Play Store, but **don't open it**.
6. Look in **Android → media → com.whatsapp**. The fresh install may have created a new, nearly empty **WhatsApp** folder. If so, **Force stop** WhatsApp (Settings → Apps) and rename that folder **WhatsApp-empty**. If com.whatsapp doesn't exist, create it.
7. Move **WA work → WhatsApp** into **com.whatsapp**. Check that **com.whatsapp/WhatsApp/Databases** holds only the merged msgstore.db.crypt15.

**Restore**

8. Open WhatsApp and verify your **phone number**. Don't use "Continue with Instagram" or another Meta account. Allow contacts, and choose **Allow all** for photos and videos.
9. On **Restore or transfer chats**, the backup's time should match the merged file, for example *"Last backup: 36 minutes ago"*. If it shows a Google backup or a different time, stop and see Troubleshooting.
10. Tap **Continue** and enter the **current phone's** 64-digit key. Keep the phone **online and on screen** while it restores. In the test it paused at 69% when Wi-Fi dropped and carried on when it reconnected.
11. After **Restore complete**, tap **Next**. You can choose **Not now** for Google backup until you've checked everything.

**Check:** old chats going back years, a chat with both old and new messages, old photos and documents, voice notes, locations and call bubbles.

**Undo:** if anything fails, reinstall WhatsApp, put **current-original.crypt15** (or your safety copy) into Databases, rename it **msgstore.db.crypt15**, and restore it. You're back where you started.

## Troubleshooting and FAQ

| Problem | What to do |
| --- | --- |
| "That key doesn't open this backup" | Each phone has its own key. Check you're using the old phone's key for the old backup and the current phone's key for the current one. |
| "no access to the phone's storage" | In Termux, run `termux-setup-storage` and tap **Allow**. |
| "not enough free space" | Free up space. The tool needs about 4.5 times the old backup's size while it works. |
| Termux stopped in the background | Set Termux's battery to **Unrestricted**, keep it on screen, plug in, and don't tap **Clean now** while it runs. Run the same command again; it continues where it stopped. |
| Quick Share won't send in airplane mode | Turn Wi-Fi on without joining a network. With no network, the phone still has no internet. |
| WhatsApp offers a **Google** backup instead of the local one | Don't restore it. Uninstall WhatsApp again (move the WhatsApp folder out first), then retry. Other users report that removing the Google account from the phone during the restore, or deleting WhatsApp's Drive backup, makes WhatsApp use the local file. Only do that once your local copies are safe. |
| Restore paused at some % | Make sure the phone is online and leave WhatsApp on screen. If Android says WhatsApp isn't responding, tap **Wait**. |
| Some chats show a number, not a name | Unsaved numbers always show as numbers. For saved contacts, give the contact sync a few minutes, or tap the new-chat button → ⋮ → **Refresh**. |
| Search doesn't find messages that were on the current phone before the merge | Fixed in the 18 November 2026 version of wa_merge.py. If you merged with an earlier version (or with wakit), see [Fix search after an earlier merge](#fix-search-after-an-earlier-merge). |
| A "not copied" list in the report | Normal. These are minor details (channels, payments, AI features) whose links the tool can't safely map, plus timers, reminders and unsent items left out on purpose. |

**Will I lose messages sent to me during the process?** No, if the phone stays offline from the final backup until the reinstall. They wait on WhatsApp's servers and arrive after the restore.

**Why are disappearing-message timers left out?** Copying them could make WhatsApp delete old disappearing messages right after the restore. Without them, those messages simply stay.

**Does this work for WhatsApp Business?** It hasn't been tested. Business uses a different app folder (`com.whatsapp.w4b`).

**Is it safe for my account?** It only uses the official WhatsApp app and your own backup files; no modified WhatsApp is involved. It is still unofficial, so use it at your own risk.

## Fix search after an earlier merge

Merges made with wa_merge.py before the evening of 18 November 2026, or with wakit 0.3.0, leave WhatsApp's search showing the wrong messages: searching a word lists messages that don't contain it, and misses ones that do. Your chats themselves are fine; only the search index is mixed up. Messages received after the restore are found normally.

Why: WhatsApp links each search entry to a message by the message's *sort id* (its place in the chat), not by its row id. On a phone that was never merged the two are almost always the same number. A merge renumbers the sort ids so the old history comes first, and the earlier versions kept the search entries keyed by row id, so WhatsApp looked up the wrong messages. The current version checks which message each entry belongs to (by its words) and writes the index keyed by sort id, the way WhatsApp does.

To fix a phone that's already merged (about 1 hour including the restore, no merging again):

1. In Termux, get the current version of the script:

```
pkg install -y python python-cryptography curl
pip install wakit==0.3.0
curl -LO https://raw.githubusercontent.com/Mousawi45/whatsapp-merge/main/wa_merge.py
```

2. Follow the offline rules: log out of linked devices, turn on airplane mode, then WhatsApp → Settings → Chats → Chat backup → **Back up**. Close WhatsApp.
3. Run:

```
python wa_merge.py --fix-search
```

   Type **yes** when it asks whether the backup is fresh, and paste **this phone's** key. It only rewrites the search index (linked by sort id, with an entry for every text message); nothing else in the backup changes. It takes about 10–20 minutes on a large backup. It shows progress every 20 seconds and saves as it goes. Keep Termux on screen with the phone charging, and set Termux's battery to **Unrestricted** (long-press the Termux icon → App info → Battery), or Android may close it partway through. If it closes anyway, just run the same command again. The result is **WA work/msgstore.db.crypt15**, with **current-original.crypt15** as your undo.
4. Follow [Restore on Android](#restore-on-android-methods-a-b-and-c), but **skip step 3** (the media is already in place).

If search still misses a message after that, run `python wa_merge.py --check-search` and paste a few words from the message. It changes nothing and prints no message text, only what the search index holds for those words (dates, chat names and counts), so you can share the output when asking for help.

## Cleanup afterwards

Use WhatsApp normally for 2–3 days first. WhatsApp makes its own backup each night, which replaces the merged file with a normal one. Then:

- [ ] **Uninstall Termux.** That also deletes the unlocked copies of your chats inside it, which can be over 10 GB.
- [ ] **Delete the unlocked `.db` files** on any computer you used, including wakit's `.bak-` copies and temp files.
- [ ] **Delete** WA-old-media, WA work, and WhatsApp-empty (in Android → media → com.whatsapp). The media is already in WhatsApp's folder.
- [ ] **Keep the original old backup file and the old phone's key** somewhere safe, such as a computer or cloud drive. It's the only copy of the untouched old history.
- [ ] **Link your devices** again: WhatsApp → Settings → Linked devices.
- [ ] **Turn on Google backup** on Wi-Fi if you use it: Settings → Chats → Chat backup. The first upload includes all the merged media, so it can be tens of GB.

## Credits, licence and disclaimer

**wakit** by Mena Maged does the heavy lifting: unlocking and re-locking backups, and the merge logic. It's free and open source under the MIT licence. If this guide helped you, star or support [wakit on GitHub](https://github.com/menaxmaged/wakit).

**wa_merge.py** adapts wakit's merge for phones and adds the extra details described in Method A. It's also MIT-licensed (see [LICENSE](LICENSE)), and wakit's copyright notice is included. Read it before running it; it's one readable Python file.

**Test setup:** Galaxy S23 Ultra to Galaxy S26 Ultra, Termux 0.118.3, Python 3.14, wakit 0.3.0, November 2026. That's 4.2 million messages and about 60,000 media files, restored successfully with the official WhatsApp app.

**Disclaimer:** not affiliated with WhatsApp or Meta. This edits your own backup files with unofficial tools. It worked in the test, but WhatsApp can change its formats at any time. Keep untouched copies of your backups and keys until you've checked the result, and use it at your own risk.

**Sources**

- [wakit on GitHub](https://github.com/menaxmaged/wakit) (README: workflows 1–5, commands and warnings) and [on PyPI](https://pypi.org/project/wakit/)
- [Termux app](https://github.com/termux/termux-app) and [Termux on F-Droid](https://f-droid.org/packages/com.termux/)
- [wa-crypt-tools](https://github.com/ElDavoo/wa-crypt-tools), another open-source tool for WhatsApp backup files

## Changes

- **18 November 2026 (late night):** found the real search bug: WhatsApp links search entries to messages by sort id, and the merge renumbers sort ids. The merge and `--fix-search` now write the index keyed by sort id, checking that each entry's words match its message. `--check-search` shows what search would return either way.
- **18 November 2026 (night):** added `--check-search`, a read-only check of why search can't find a message.
- **18 November 2026 (evening):** writing the new backup no longer loads the whole original backup into memory. With large backups (over about 0.5 GB) Android closed Termux right after "index checked" (the merge was affected too). `--fix-search` also shows which months the filled-in entries are from.
- **18 November 2026 (later):** the search fix uses much less memory: it works in slices, shows progress every 20 seconds, saves as it goes, and rebuilds the index only if it's inconsistent. On some phones the earlier version froze and Android closed Termux during this step.
- **18 November 2026:** the merge now completes and rebuilds WhatsApp's search index, so messages that were on the current phone before the merge can be found with search. Added `--fix-search` for phones merged with an earlier version.
- **17 November 2026:** first version.
