# Kannada Health and Fitness

Chat and video calls in Kannada and English. This is a starter version.

## Run on your computer
1. Install Node.js 18 or newer.
2. Set up Google sign-in (below). Run `npm install`, then start with your Client ID. Mac or Linux: `GOOGLE_CLIENT_ID=your-id npm start`. Windows PowerShell: `$env:GOOGLE_CLIENT_ID="your-id"; npm start`.
3. Open http://localhost:3000 in a normal window and a private window, sign in with two different Google accounts, chat, and press the video call button.

## Google sign-in setup
1. Open Google Cloud Console, then APIs & Services, then Credentials, then Create credentials, then OAuth client ID, type Web application. (The first time, it asks you to fill in the OAuth consent screen.)
2. Under Authorized JavaScript origins add `http://localhost`, `http://localhost:3000` and your live https link (for example `https://your-app.onrender.com`).
3. Copy the Client ID (it ends with `.apps.googleusercontent.com`). Give the server two environment variables: `GOOGLE_CLIENT_ID` (that Client ID) and `SESSION_SECRET` (any long random text). On Render or Railway add them in the Environment settings.
4. While the consent screen is in Testing mode only the test users you list can sign in. Press Publish app so everyone can.

Only the Google name is shown to other people. The email address is never shared. People stay signed in for 30 days. If the same account signs in on a second device or tab, the first one is signed out.

## Put it on GitHub and make it live
1. Create a GitHub repository and upload all these files (keep the `public` folder).
2. GitHub only stores the code. GitHub Pages cannot run this Node server, so deploy the repository on a Node host such as Render or Railway. Build command: `npm install`. Start command: `npm start`.
3. Open the https link the host gives you. Camera and microphone need https.

## What works
- Real-time chat, group channels (yoga, diet, weight loss, general), and 1-to-1 chat
- Message history saved with no message limit, loaded 30 at a time
- Spam limit of 20 messages per 10 seconds per user
- 1-to-1 video calls, Kannada and English switch

## Not built yet
Phone OTP login, a real database (PostgreSQL), push notifications, photos and voice notes, group calls, a TURN server for strict networks, trainer and doctor verification, payments, a privacy policy, and Android and iPhone apps.

Messages are saved in `data/messages.jsonl`. Many hosts erase the disk on restart, so move to a database before real users.
