# Attendance Portal
Check in/out, leave requests with admin approval, and a monthly attendance dashboard.
Stack: Node + Express + PostgreSQL, plain HTML frontend. The first account registered becomes admin.

## Run locally
    npm install
    DATABASE_URL=postgres://user:pass@localhost:5432/attendance JWT_SECRET=anything npm start
