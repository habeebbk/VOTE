COLLEGE TRIP VOTING - RUN INSTRUCTIONS

Needs Python 3.9+ (pymongo installed if using MongoDB, or zero packages needed if using local SQLite).

Windows PowerShell / Terminal:
  cd path\to\college_vote_project
  # Configure settings in .env (or pass environment variables):
  python server.py

Open http://localhost:8000
Admin http://localhost:8000/admin

IMPORTANT:
- This is a local server, not a public link. To share over the internet deploy the whole folder on a Python-compatible HTTPS host with persistent disk.
- votes.db is created on first run. Timer starts at FIRST RUN, not at first student vote.
- The voter CSV is private: NEVER put it in a public web directory, repository, or public link.
- Admin can see individual votes. Tell students before voting.
- PINs are only 4 digits. Rate limits help but this is for a small, low-stakes class poll.
- Do not delete votes.db before exporting results. Keep a private backup.
- Changing the CSV after first run does not change imported students.
- Admin password must be at least 12 characters.
- Admin CSV export includes full phone numbers; keep it private.
- For public deployment, add reverse proxy HTTPS and durable sessions (this simple app keeps sessions in memory).
