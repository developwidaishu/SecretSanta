# 🎅 Secret Santa Workshop

A local web app that draws Secret Santa names and emails every Santa their giftee, **without the organisers ever seeing who got whom.** You only need Python 3.9 or newer. There's nothing to `pip install`.

## Run it
Double-click `start.bat`, or run `python server.py`. It opens http://127.0.0.1:8765.

## Organiser flow
1. **Event**: check the budget, dates and location. Click *Preview a mission letter*.
2. **Santas**: in the Google Form responses sheet, select all and copy, then paste here.
   It finds these columns by name: **Name**, **Email**, **Wishlist / hints**, **Avoid** (optional).
   - Add *"Any hints for your Santa?"* and *"Anyone you'd rather not be paired with? (email)"* to the form.
3. **Mailbox**: create a **new Gmail just for this** (e.g. `blr.secret.santa@gmail.com`).
   Turn on 2-Step Verification, then make an **App Password** (myaccount.google.com/apppasswords) and paste it in.
   The password is kept in memory only and never written to disk. Send yourself a test letter.
4. **Draw & Send**: one click. Track delivery, resend lost letters, or send a nudge (e.g. the voted exchange day).
5. **Exchange Day**: put it on the projector, type REVEAL, and unmask each codename one card at a time.

## How the secret stays secret
- The draw runs on your machine and pairings go straight into emails. No screen shows them until the reveal.
- Pairings are kept in an encrypted vault (`data/vault.sealed`), so resends and the reveal work.
- **Shred** (on by default) deletes the robot mailbox's *Sent* copies over IMAP right after sending.
- After the draw the roster is **locked**, so nobody can change an email address to intercept someone's letter.
- **Burn the key** once everyone has their letter, if you want to be extra careful. After that, nobody can ever read the pairings.

Honest caveat: someone with access to this computer who goes digging (reading `data/vault.key` and the code) could still decrypt the vault. This protects against accidental peeking, not a determined organiser. Burning the key closes that gap.
