# 🎅 Santa's Sleigh Desk

A local web app that draws Secret Santa names and emails every Santa their giftee, **without the organisers ever seeing who got whom.** You only need Python 3.9 or newer. There's nothing to `pip install`.

## Run it
Double-click `start.bat`, or run `python server.py`. It opens http://127.0.0.1:8765.

## Organiser flow
1. **Event**: check the exchange dates. Click *Preview a mission letter*.
2. **Santas**: in Google Forms go to Responses, then the ⋮ menu, then *Download responses (.csv)*, and pick that file
   (or paste the whole responses sheet, header row included). The app uses **Your name**, **E-mail**,
   **Gifts I do not want** (shown in the letter) and **...remain anonymous...** (those Santas are never unmasked
   on Exchange Day). If the form has a **secret Santa name** question, that becomes the person's codename. Anyone who left it
   blank gets one auto-assigned. Chosen names are never shown in the organiser screens. Other columns are ignored.
   - If the roster says it's locked from a trial run, click *Clear the old draw & unlock* first.
3. **Mailbox**: create a **new Gmail just for this** (e.g. `blr.secret.santa@gmail.com`).
   Turn on 2-Step Verification, then make an **App Password** (myaccount.google.com/apppasswords) and paste it in.
   The password is kept in memory only and never written to disk. Send yourself a test letter.
4. **Draw & Send**: one click. Track delivery, resend lost letters, or send a nudge (e.g. the voted exchange day).
   - **Late joiners** (after the draw): on the **Santas** tab, use the *Late joiners* box. Either pick a freshly
     downloaded responses .csv (only people not already on the list get added) or add someone by hand. Once at
     least 2 are waiting, click *Draw the late joiners & send their letters* on **Draw & Send**. They get their own
     small gift loop (with exactly 2, they gift each other). Nobody from the main draw is changed or emailed. A small
     draw list for that batch downloads too. You can do this more than once. Each wave becomes its own loop.
     Tip: don't announce that late joiners form their own group. The letters never mention it.
5. **Exchange Day**: click *Open Exchange Day screen*. It opens in its own window. Type REVEAL on your laptop, then drag the window to the projector and press F for full screen. Use → / Space or a clicker to unmask each card and move on, and ← to go back. Gifts appear in random order (late joiners are mixed in with everyone else), and Santas who chose to stay anonymous are never named.

## Full mapping file (for the organiser)
- Right after the main draw, and after each late-joiner draw, a plain text file downloads:
  `secret-santa-full-mapping-YYYYMMDD-HHMM.txt`. It always covers **everyone**: the main draw plus all late loops.
- Need a fresh copy later? **Draw & Send** tab, then *Download full mapping*.
- Inside: every pairing, each Santa's codename, who asked to stay anonymous, and a "for the reveal" list sorted by who
  got the gift. If the app can't run on Exchange Day, read the reveal from that list.
- It's plain text, so only the organiser should keep it. It stops working once the vault key is burned.

## Backups & going back to an earlier stage (💾 Backups tab)
- **Download backup**: saves everything (Santa list, the draw, late joiners, who got their letter) in one `.json` file,
  locked with a passphrase you choose. Lose the passphrase and the file can't be opened, by anyone.
- **Restore from file**: pick that file and type its passphrase. The app carries on from exactly that point,
  on this laptop or another one. Restoring never sends emails by itself.
- **Automatic restore points**: saved after every import, draw, late-joiner change and batch of letters, and just
  before any restore or start-over. Click *Restore* on any row to go back to it. A restore can itself be undone.
- Letters already sent stay sent. Going back to before a draw and drawing again gives people a second, different letter.
- Burning the vault key also wipes the key from the restore points, but not from files you've already downloaded.
  Delete those yourself.

## How the secret stays secret
- The draw runs on your machine and pairings go straight into emails. No screen shows them until the reveal.
- Pairings are kept in an encrypted vault (`data/vault.sealed`), so resends and the reveal work.
- **Shred** (on by default) deletes the robot mailbox's *Sent* copies over IMAP right after sending.
- After the draw the roster is **locked**, so nobody can change an email address to intercept someone's letter.
  Late joiners can only be *added*, never used to edit someone who is already drawn.
- **Burn the key** once everyone has their letter, if you want to be extra careful. After that, nobody can ever read the pairings.

Honest caveat: someone with access to this computer who goes digging (reading `data/vault.key` and the code) could still decrypt the vault. This protects against accidental peeking, not a determined organiser. Burning the key closes that gap.
