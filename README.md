# 🎅 Santa's Sleigh Desk

A local web app that draws Secret Santa names and emails every Santa their giftee, **without the organisers ever seeing who got whom.** You only need Python 3.9 or newer. There's nothing to `pip install`.

## Run it
Double-click `start.bat`, or run `python server.py`. It opens http://127.0.0.1:8765.

## Organiser flow
1. **Event**: check the exchange dates. Click *Preview a mission letter*.
2. **Santas**: in Google Forms go to Responses, then the ⋮ menu, then *Download responses (.csv)*, and pick that file
   (or paste the whole responses sheet, header row included). The app uses **Your name**, **E-mail**,
   **Gifts I do not want** (shown in the letter) and **...remain anonymous...** (those Santas are never unmasked
   on Exchange Day). Other columns are ignored.
   - If the roster says it's locked from a trial run, click *Clear the old draw & unlock* first.
3. **Mailbox**: create a **new Gmail just for this** (e.g. `blr.secret.santa@gmail.com`).
   Turn on 2-Step Verification, then make an **App Password** (myaccount.google.com/apppasswords) and paste it in.
   The password is kept in memory only and never written to disk. Send yourself a test letter.
4. **Draw & Send**: one click. Track delivery, resend lost letters, or send a nudge (e.g. the voted exchange day).
5. **Exchange Day**: click *Open Exchange Day screen*. It opens in its own window. Type REVEAL on your laptop, then drag the window to the projector and press F for full screen. Use → / Space or a clicker to unmask each card and move on, and ← to go back. Gifts appear in random order, and Santas who chose to stay anonymous are never named.

## How the secret stays secret
- The draw runs on your machine and pairings go straight into emails. No screen shows them until the reveal.
- Pairings are kept in an encrypted vault (`data/vault.sealed`), so resends and the reveal work.
- **Shred** (on by default) deletes the robot mailbox's *Sent* copies over IMAP right after sending.
- After the draw the roster is **locked**, so nobody can change an email address to intercept someone's letter.
- **Burn the key** once everyone has their letter, if you want to be extra careful. After that, nobody can ever read the pairings.

Honest caveat: someone with access to this computer who goes digging (reading `data/vault.key` and the code) could still decrypt the vault. This protects against accidental peeking, not a determined organiser. Burning the key closes that gap.
