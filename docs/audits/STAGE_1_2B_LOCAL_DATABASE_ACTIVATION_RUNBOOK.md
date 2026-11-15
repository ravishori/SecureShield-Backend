# Stage 1.2B: supervised local database activation runbook

Prepared 2026-11-15. **Nothing in this document has been executed.** It is a procedure for **you** to run by hand, on your own machine, in your own PowerShell window, one checkpoint at a time. Claude has not connected to PostgreSQL, run `psql`, run the SQL, created a role or database, set a password, started the backend or run Alembic.

| | |
|---|---|
| SQL file | `backend\docs\database\STAGE_1_2_LOCAL_DATABASE_SETUP.sql` (293 lines, pure ASCII, LF) |
| SQL SHA-256 | `CC6A851B48DBEFD2B87046137E91648C6BE410A54AE34CD4695140EE94EE9B06` |
| Reviewed in | `STAGE_1_2_IMPLEMENTATION_REPORT.md`, `STAGE_1_2A_SQL_REVIEW_REPORT.md` (verdict: approved with conditions) |
| Server | local PostgreSQL 18, service `postgresql-x64-18`, `localhost:5432`, data directory `D:\Program Files\PostgreSQL\18\data` |
| Result you are aiming for | databases `secureshield_dev` and `secureshield_test`, roles `secureshield_dev_owner`, `secureshield_dev_app`, `secureshield_test_owner`, three passwords set, no schema yet |

**Not part of this runbook (separate approvals later):** `alembic upgrade head`, starting the backend, integration tests, any data. This runbook creates empty databases only.

---
## 0. Ground rules (read once)
1. **One rule above all: if anything differs from what this document says to expect, STOP.** Do not retry, do not edit the SQL, do not "fix" it. Save the output and send it for review (section 9).
2. Never type a password into a command line, a file you will commit, or this chat. Passwords are typed only at hidden prompts (`\password`, `psql` login) and into your untracked `.env.local`.
3. Never run `DROP`, `TRUNCATE`, `DELETE`, `pg_dump`/`pg_restore` against these databases, or `psql --single-transaction` / `-1` (it breaks `CREATE DATABASE`).
4. Run everything from PowerShell in `D:\ravishori\SecureShieldApp\backend` unless a step says otherwise. Do not run anything as Administrator unless Windows itself demands it.
5. Approval checkpoints are marked **CHECKPOINT n**. At each one you decide to go on; nothing proceeds on its own.

Variables used throughout (paste once per PowerShell window):
```powershell
Set-Location 'D:\ravishori\SecureShieldApp\backend'
$psql  = 'D:\Program Files\PostgreSQL\18\bin\psql.exe'
$admin = @('-X','-h','localhost','-p','5432','-U','postgres','-d','postgres')   # explicit host/port/user/db; -X ignores any psqlrc
$sql   = 'D:\ravishori\SecureShieldApp\backend\docs\database\STAGE_1_2_LOCAL_DATABASE_SETUP.sql'
$act   = 'C:\SecureShieldActivation\2026-11-15'                                 # evidence folder, outside the repository, on C:
```

---
## 1. Preconditions (all must hold)
### 1.1 The service
```powershell
Get-Service postgresql-x64-18, PostgreSQL18 | Format-Table Name, Status, StartType
```
Expect `postgresql-x64-18` **Running**. Expect `PostgreSQL18` **Stopped** and leave it stopped (it is a second service for the same installation; never start both). **STOP** if `postgresql-x64-18` is not Running or `PostgreSQL18` is Running.

### 1.2 Nothing in your shell can redirect psql
```powershell
Get-ChildItem Env: | Where-Object { $_.Name -like 'PG*' -or $_.Name -in 'DATABASE_URL','MIGRATOR_DATABASE_URL','TEST_DATABASE_URL','SECURESHIELD_ENV_FILE' } | Format-Table Name
```
Expect **no rows**. If a `PG*` variable exists (for example `PGHOST` or `PGSERVICE` left over from the Neon work), **STOP**, close the window and open a new one (or `Remove-Item Env:PGHOST`); the commands below pass host, port, user and database explicitly, but a leftover must not exist at all. Also confirm there is no `%APPDATA%\postgresql\pg_service.conf` that could define a service named like your target.

### 1.3 The client and the server accept connections, and it is the local one
```powershell
& $psql --version                                   # expect: psql (PostgreSQL) 18.x
& 'D:\Program Files\PostgreSQL\18\bin\pg_isready.exe' -h localhost -p 5432   # expect: localhost:5432 - accepting connections
```
Then confirm the server really is this machine's installation (enter the `postgres` password when prompted):
```powershell
& $psql @admin -c "SELECT version(), inet_server_addr() AS addr, inet_server_port() AS port, current_setting('data_directory') AS data_dir, current_setting('password_encryption') AS pw_enc, current_setting('listen_addresses') AS listen, current_user AS me, (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) AS superuser;"
```
| Column | Expected |
|---|---|
| version | `PostgreSQL 18.x ... windows` |
| addr | `127.0.0.1` or `::1` (empty/NULL is also fine for a Unix socket) |
| port | `5432` |
| data_dir | `D:/Program Files/PostgreSQL/18/data` |
| pw_enc | `scram-sha-256` |
| listen | `*` (known; remote clients are still rejected by `pg_hba.conf`, see 1.6) |
| me / superuser | `postgres` / `t` |
**STOP** if the data directory is anywhere else, the address is not loopback, the password encryption is not `scram-sha-256`, or you are not a superuser.

### 1.4 Disk space
```powershell
Get-PSDrive C, D | Select Name, @{n='FreeGB';e={[math]::Round($_.Free/1GB,2)}}
```
The data directory is on **D:** (1.77 GB free when this was prepared). Two empty databases need about 20 MB plus transient WAL. Require **at least 500 MB free on D:** and at least 1 GB on C: for the evidence folder. **STOP** below that.

### 1.5 The names are free and nobody is using template1
```powershell
& $psql @admin -c "SELECT rolname FROM pg_roles WHERE rolname LIKE 'secureshield\_%' ORDER BY 1;" -c "SELECT datname FROM pg_database WHERE datname LIKE 'secureshield\_%' ORDER BY 1;" -c "SELECT count(*) AS sessions_on_template1 FROM pg_stat_activity WHERE datname = 'template1';"
```
Expect: **0 rows, 0 rows, `0`**. If any `secureshield_dev*` / `secureshield_test*` role or database already exists, **STOP and report it** (the script would reuse it only after checks; that is a decision to make together). A role/database named exactly `SecureShieldDB` is the legacy migration source: that is expected and must not be touched.

### 1.6 Authentication rules
```powershell
& $psql @admin -c "SELECT line_number, type, database, user_name, address, auth_method FROM pg_hba_file_rules ORDER BY line_number;"
```
Expect only `local` and loopback `host` (127.0.0.1/32, ::1/128) lines, all `scram-sha-256` (this is what the file contained when read on 2026-11-15). **STOP** on any `trust`, `md5`/`password`, or non-loopback address.

### 1.7 The SQL is exactly the reviewed file
```powershell
(Get-FileHash -Algorithm SHA256 $sql).Hash                 # must equal CC6A851B48DBEFD2B87046137E91648C6BE410A54AE34CD4695140EE94EE9B06
(Get-Content $sql).Count                                   # must be 293
Select-String -Path $sql -Pattern 'DROP|TRUNCATE|PASSWORD ''' -CaseSensitive | ForEach-Object { $_.LineNumber }   # must print exactly 10 and 192 (two COMMENT lines that mention TRUNCATE); no DROP, no password literal
```
**STOP** if the hash differs (someone edited the file; ask for a re-review).

### 1.8 Prepare the evidence folder and the part files
`CREATE DATABASE` must run outside a transaction, and you want to inspect each part before the next one, so the file is cut into six part files at its own part boundaries. Each part file starts with the script's two `\set` lines. The cut is mechanical and is checked against the original:
```powershell
New-Item -ItemType Directory -Path $act | Out-Null          # fails if it already exists: pick a new folder, never reuse one
$lines = [IO.File]::ReadAllLines($sql)
if ($lines.Count -ne 293) { throw "unexpected line count" }
$pre = $lines[66..68]                                        # lines 67-69: \set ON_ERROR_STOP on / comment / \set AUTOCOMMIT on
$ranges = [ordered]@{ part0=@(71,98); part1=@(100,143); part2=@(145,169); part3=@(171,186); part4=@(188,218); part5=@(220,293) }
foreach ($n in $ranges.Keys) {
  $a,$b = $ranges[$n]
  [IO.File]::WriteAllText("$act\$n.sql", ((@($pre) + '' + @($lines[($a-1)..($b-1)])) -join "`n") + "`n", [Text.Encoding]::ASCII)
}
$rebuilt = foreach ($n in $ranges.Keys) { $a,$b = $ranges[$n]; $lines[($a-1)..($b-1)] }
$same = -not (Compare-Object ($lines[70..292] | Where-Object { $_ -ne '' }) ($rebuilt | Where-Object { $_ -ne '' }) -SyncWindow 0)
"parts identical to the original (blank lines aside): $same"      # must print True
Get-ChildItem $act\part*.sql | Format-Table Name, Length
```
Expected sizes (bytes, approximately): part0 2068, part1 2396, part2 1732, part3 1050, part4 1524, part5 5053 (these were measured on the unchanged file). **STOP** if it does not print `True`.

Record the inventory (read-only) for the evidence package, then decide:
```powershell
& $psql @admin -c "\du+" -c "\l+" -c "SELECT current_timestamp AS taken_at;" 2>&1 | Tee-Object -FilePath "$act\00_inventory_before.txt"
```
(`\du+` shows role attributes, never password hashes.)

> **CHECKPOINT 1: preconditions.** Sections 1.1 to 1.8 all matched. Only then continue. (Optional: send `00_inventory_before.txt` and the 1.3 output for a second look before Part 1.)

---
## 2. Running the parts, in order
The same helper for every part. It stops psql at the first error (`ON_ERROR_STOP=1`), echoes every statement (`-a`), keeps a copy of everything you see, and prints psql's exit code (0 = fine; 3 = a statement failed; 2 = could not connect). psql will ask for the `postgres` password at each run (hidden prompt).
```powershell
function Run-Part([string]$n) {
  & $psql @admin -v ON_ERROR_STOP=1 -a -b -f "$act\$n.sql" 2>&1 | Tee-Object -FilePath "$act\$n.out.txt"
  "---- $n finished, psql exit code: $LASTEXITCODE ----"
}
```
**After each part:** the exit code must be 0, the output must contain no line starting with `ERROR:`, `FATAL:` or `WARNING:`, and it must contain exactly the command tags listed. Anything else: **STOP**.

### Part 0: precheck (read-only)
```powershell
Run-Part part0
```
Expect exactly one `DO` and exit code 0. A message beginning `refusing to run:` means a guard fired (non-loopback, hosted-service fingerprint, wrong database, old server, or not a superuser): **STOP**, do not work around it.

### Part 1: roles (one transaction)
```powershell
Run-Part part1
```
Expect, in order: `BEGIN`, `DO`, `DO`, `COMMIT`. After it the three roles exist with LOGIN, **no password**, and no special privilege. An error such as `existing role(s) ... hold more than least privilege` rolled the whole part back: **STOP** and report.

### Part 2: databases (autocommit, not in a transaction)
```powershell
Run-Part part2
```
Expect: `CREATE DATABASE`, `CREATE DATABASE`, `DO` (on a first run; a re-run prints only `DO`). Error `source database "template1" is being accessed by other users`: close whatever uses it (re-check 1.5) and run `Run-Part part2` again; that is the only retry this runbook permits, and only for that exact message.

### Part 3: who may connect (one transaction)
```powershell
Run-Part part3
```
Expect: `BEGIN`, `REVOKE`, `REVOKE`, `GRANT`, `GRANT`, `REVOKE`, `REVOKE`, `COMMIT`.

### Part 4: schema privileges (one transaction per database)
```powershell
Run-Part part4
```
Expect, in order: `You are now connected to database "secureshield_dev" as user "postgres".`, `BEGIN`, `REVOKE`, `GRANT`, `ALTER DEFAULT PRIVILEGES`, `ALTER DEFAULT PRIVILEGES`, `COMMIT`, then `You are now connected to database "secureshield_test" ...`, `BEGIN`, `REVOKE`, `COMMIT`, then `You are now connected to database "postgres" ...`. (psql may ask for the password again at each connect; that is normal.)

> **CHECKPOINT 2: Parts 0 to 4 clean.** Every exit code 0 and every tag as listed. Continue only if so.

### Part 5: verification (read-only)
```powershell
Run-Part part5
```
This is the acceptance check. Compare every result set with section 3.

---
## 3. Expected Part 5 results (the acceptance table)
Passwords are not set yet, so `has_password` is `f` here. Column separators below are psql's `|`.

**5.1: roles. Exactly 3 rows**
```
          rolname          | can_login | superuser | create_db | create_role | replication | bypass_rls | inherit | connection_limit | has_password
---------------------------+-----------+-----------+-----------+-------------+-------------+------------+---------+------------------+--------------
 secureshield_dev_app      | t         | f         | f         | f           | f           | f          | f       |               50 | f
 secureshield_dev_owner    | t         | f         | f         | f           | f           | f          | f       |               20 | f
 secureshield_test_owner   | t         | f         | f         | f           | f           | f          | f       |               20 | f
```
Any `t` in superuser, create_db, create_role, replication, bypass_rls or inherit, or `t` in has_password: **STOP**. (`has_password` comes from `pg_authid` and is only "is one set"; no hash is ever selected or shown.)

**5.1b: authentication. 0 rows** (`pg_hba_file_rules` lines whose method is `trust`). Any row: **STOP**.

**5.2: role membership. 0 rows.** Any row: **STOP**.

**5.3: databases and owners. Exactly 2 rows**
```
      datname      |          owner          | encoding | allow_connections
-------------------+-------------------------+----------+-------------------
 secureshield_dev  | secureshield_dev_owner  | UTF8     | t
 secureshield_test | secureshield_test_owner | UTF8     | t
```
A different owner, or an encoding other than UTF8: **STOP**.

**5.4: connection privileges. Exactly 6 rows**
```
      datname      |         rolname         | can_connect
-------------------+-------------------------+-------------
 secureshield_dev  | secureshield_dev_app    | t
 secureshield_dev  | secureshield_dev_owner  | t
 secureshield_dev  | secureshield_test_owner | f
 secureshield_test | secureshield_dev_app    | f
 secureshield_test | secureshield_dev_owner  | f
 secureshield_test | secureshield_test_owner | t
```
Any other value, above all `t` for `secureshield_test_owner` on `secureshield_dev` or for a dev role on `secureshield_test`: **STOP**.

**5.5: unexpected non-owner grantees. Exactly 1 row**
```
     datname      |       grantee        | privilege_type
------------------+----------------------+----------------
 secureshield_dev | secureshield_dev_app | CONNECT
```
A `PUBLIC` row, any other role, any other privilege, or any row for `secureshield_test`: **STOP** (somebody granted access outside this script).

**5.6: informational.** 0 or 1 rows (`SecureShieldDB`, the legacy migration source). A row is expected on this machine and is not a problem. Never use it as a development database.

**5.7: server identity.** `server_address` `127.0.0.1` or `::1` (or empty), `server_port` `5432`, `version` `18.x`.

**5.8: schema ACLs (the script lists them as comments; run them by hand).**
```powershell
& $psql -X -h localhost -p 5432 -U postgres -d secureshield_dev  -c "SELECT nspname, nspacl FROM pg_namespace WHERE nspname = 'public';" -c "SELECT defaclrole::regrole AS grantor, defaclobjtype AS object_type, defaclacl FROM pg_default_acl;" 2>&1 | Tee-Object -FilePath "$act\part5_8_dev.txt"
& $psql -X -h localhost -p 5432 -U postgres -d secureshield_test -c "SELECT nspname, nspacl FROM pg_namespace WHERE nspname = 'public';" 2>&1 | Tee-Object -FilePath "$act\part5_8_test.txt"
```
Expected shape (the point is: **no entry that starts with `=`**, which would be PUBLIC):
- dev `public` nspacl: `{pg_database_owner=UC/pg_database_owner,secureshield_dev_app=U/pg_database_owner}`
- dev default ACLs, exactly 2 rows, grantor `secureshield_dev_owner`: type `r` (tables) `{secureshield_dev_app=arwd/secureshield_dev_owner}`, type `S` (sequences) `{secureshield_dev_app=rU/secureshield_dev_owner}`
- test `public` nspacl: `{pg_database_owner=UC/pg_database_owner}`

> **CHECKPOINT 3: Part 5 matches.** Strongly recommended: send `part5.out.txt`, `part5_8_*.txt` and the earlier `*.out.txt` for review **before** setting passwords (section 9). If every line matched exactly you may continue, but if there is any doubt, stop here.

---
## 4. Set the passwords (interactive, hidden)
Rules for the passwords: one **different** password per role, at least 24 random characters, **letters and digits only** (so nothing needs URL-encoding in a connection URL), kept in your password manager. They must never appear in a file you commit, in a shell command, or in chat.
```powershell
& $psql @admin
```
At the `postgres=#` prompt type these three commands, one at a time. psql asks for the password twice, with no echo, and sends only a SCRAM hash:
```
\password secureshield_dev_owner
\password secureshield_dev_app
\password secureshield_test_owner
\q
```
(Do not capture a transcript of this session.) Then confirm each role now has a password, **without** showing any hash:
```powershell
& $psql @admin -c "SELECT rolname, (rolpassword IS NOT NULL) AS has_password FROM pg_authid WHERE rolname IN ('secureshield_dev_owner','secureshield_dev_app','secureshield_test_owner') ORDER BY rolname;" 2>&1 | Tee-Object -FilePath "$act\10_has_password.txt"
```
Expect 3 rows, all `has_password = t`. **Never** run a query that selects `rolpassword` itself.

> **CHECKPOINT 4: passwords set.**

---
## 5. Prove the privileges (each role logs in with its own password)
Each command prompts for that role's password (hidden). The *expected failure* lines are the point of the test.
```powershell
$ro = @('-X','-h','localhost','-p','5432')
$out = "$act\11_proofs.txt"
"P1 dev_app -> dev (must WORK)";            & $psql @ro -U secureshield_dev_app    -d secureshield_dev  -c "SELECT current_user, current_database();" 2>&1 | Tee-Object -FilePath $out -Append
"P2 dev_owner -> dev (must WORK)";          & $psql @ro -U secureshield_dev_owner  -d secureshield_dev  -c "SELECT current_user, current_database();" 2>&1 | Tee-Object -FilePath $out -Append
"P3 test_owner -> test (must WORK)";        & $psql @ro -U secureshield_test_owner -d secureshield_test -c "SELECT current_user, current_database();" 2>&1 | Tee-Object -FilePath $out -Append
"P4 dev_app -> test (must FAIL)";           & $psql @ro -U secureshield_dev_app    -d secureshield_test -c "SELECT 1;" 2>&1 | Tee-Object -FilePath $out -Append
"P5 test_owner -> dev (must FAIL)";         & $psql @ro -U secureshield_test_owner -d secureshield_dev  -c "SELECT 1;" 2>&1 | Tee-Object -FilePath $out -Append
```
Expected: P1 to P3 print the user and database. **P4 and P5 must print** `FATAL:  permission denied for database "secureshield_test"` / `"secureshield_dev"`. If P4 or P5 connect, **STOP**.

The next two prove that the application role cannot change the schema or administer roles. They run inside a transaction that is always rolled back, so even a wrong result changes nothing:
```powershell
"P6 dev_app cannot create a table (must FAIL)"
"BEGIN;`nCREATE TABLE should_fail (id int);`nROLLBACK;`n" | & $psql @ro -U secureshield_dev_app -d secureshield_dev -f - 2>&1 | Tee-Object -FilePath $out -Append
"P7 dev_app cannot create a role (must FAIL)"
"BEGIN;`nCREATE ROLE should_fail LOGIN;`nROLLBACK;`n" | & $psql @ro -U secureshield_dev_app -d secureshield_dev -f - 2>&1 | Tee-Object -FilePath $out -Append
"P8 dev_app cannot create a database (must FAIL)"
& $psql @ro -U secureshield_dev_app -d secureshield_dev -c "CREATE DATABASE should_fail;" 2>&1 | Tee-Object -FilePath $out -Append
```
Expected: P6 `ERROR:  permission denied for schema public`; P7 `ERROR:  permission denied to create role`; P8 `ERROR:  permission denied to create database`. If any of them **succeeds**, **STOP immediately and report** (for P6/P7 the `ROLLBACK` undoes it; P8 has no rollback, which is why a success there would need a report before anything else is done).

> **CHECKPOINT 5: the access matrix behaves as designed.**

---
## 6. Create `.env.local` and verify the selected targets (no connection is made by these commands)
### 6.1 Static check with dummy values (proves the code and the names; uses no real password)
```powershell
$dummy = @{ SECRET_KEY='check-only'; SMTP_HOST='localhost'; SMTP_PORT='1025'; SMTP_USER='check'; SMTP_PASSWORD='check'; SMTP_FROM_EMAIL='check@example.com'; ERROR_NOTIFY_EMAIL='check@example.com'; TWILIO_ACCOUNT_SID='disabled-local'; TWILIO_AUTH_TOKEN='disabled'; TWILIO_SMS_NUMBER='+10000000000'; TWILIO_WHATSAPP_NUMBER='+10000000000' }
foreach ($k in $dummy.Keys) { Set-Item "Env:$k" $dummy[$k] }
Remove-Item Env:SECURESHIELD_ENV_FILE -ErrorAction SilentlyContinue

# development target
$env:ENVIRONMENT = 'development'; $env:DATABASE_ENVIRONMENT = 'local'
$env:DATABASE_URL         = 'postgresql+asyncpg://secureshield_dev_app:CHECK_ONLY@localhost:5432/secureshield_dev'
$env:MIGRATOR_DATABASE_URL = 'postgresql+asyncpg://secureshield_dev_owner:CHECK_ONLY@localhost:5432/secureshield_dev'
.\.venv\Scripts\python.exe -m app.cli.show_database_target --expect development 2>&1 | Tee-Object -FilePath "$act\20_target_dev_static.txt"; "exit: $LASTEXITCODE"

# test target
$env:ENVIRONMENT = 'test'; $env:DATABASE_ENVIRONMENT = 'test'
$env:DATABASE_URL = $env:MIGRATOR_DATABASE_URL = 'postgresql+asyncpg://secureshield_test_owner:CHECK_ONLY@localhost:5432/secureshield_test'
.\.venv\Scripts\python.exe -m app.cli.show_database_target --expect test 2>&1 | Tee-Object -FilePath "$act\21_target_test_static.txt"; "exit: $LASTEXITCODE"

# clean up this window
$dummy.Keys + 'ENVIRONMENT','DATABASE_ENVIRONMENT','DATABASE_URL','MIGRATOR_DATABASE_URL' | ForEach-Object { Remove-Item "Env:$_" -ErrorAction SilentlyContinue }
```
Expected output of the development check (this exact output was produced when the command was dry-run for this runbook; the first line is a harmless notice that `backend/.env` is not read):
```
backend/.env exists but is NOT read (no implicit .env loading). Set SECURESHIELD_ENV_FILE to select an environment file explicitly.
database identity OK: environment=development class=loopback database=secureshield_dev
environment          : development / local
server               : localhost:5432
database             : secureshield_dev
runtime role         : secureshield_dev_app  (DATABASE_URL)
migrator role        : secureshield_dev_owner  (MIGRATOR_DATABASE_URL)
connection           : none made by this command
exit: 0
```
and of the test check: the same shape with `environment=test class=loopback database=secureshield_test`, `environment : test / test`, both roles `secureshield_test_owner`, `exit: 0`. **STOP** on any `PROBLEM:` or `REFUSED:` line or a non-zero exit.

### 6.2 The real development file
```powershell
if (Test-Path .env.local) { throw ".env.local already exists: do not overwrite it, edit it instead" }   # Copy-Item would silently overwrite
Copy-Item .env.example .env.local
git check-ignore -v .env.local                         # expect: .gitignore:3:.env.*    .env.local   (it is ignored and will never be committed)
notepad .env.local
```
In the editor: replace `YOUR_DEV_APP_PASSWORD` and `YOUR_DEV_OWNER_PASSWORD` with the two passwords (letters and digits only). Besides the two database URLs, set `SECRET_KEY=` (any long random string) and keep `SMTP_PORT=587` (it stays a required integer). **Since Stage 1.2D the e-mail and SMS settings are optional**: leave `SMTP_*`, `ERROR_NOTIFY_EMAIL` and `TWILIO_*` empty and nothing is sent (the application reports "not configured"); you no longer need placeholder values for them. Leave `ANTHROPIC_API_KEY`, `RESEND_API_KEY`, `RETENTION_CLEANUP_ENABLED` and `GUARDIAN_WORKER_ENABLED` unset/empty. Save. Do not put `TEST_DATABASE_URL` in this file.

Then check the real file (still makes **no** connection and prints no password):
```powershell
$env:SECURESHIELD_ENV_FILE = '.env.local'
.\.venv\Scripts\python.exe -m app.cli.show_database_target --expect development 2>&1 | Tee-Object -FilePath "$act\22_target_dev_real.txt"; "exit: $LASTEXITCODE"
Remove-Item Env:SECURESHIELD_ENV_FILE
```
Expect exactly the development output above **without** the first notice line, and `exit: 0`. If it prints `PROBLEM: the runtime and migrator URLs use the SAME role`, you pasted the same password/role into both URLs: fix the file. A pydantic "Field required" error means one of the inert values above is missing.

> **CHECKPOINT 6: activation complete as a database set-up.** Send the evidence package (section 9). **Do not run Alembic or start the backend yet**: those need a separate approval after the evidence is reviewed.

---
## 7. If anything goes wrong: stopping, recovery and rollback (nothing here is destructive)
**Stop immediately** means: do not run another command in that window; do not re-run the failing part; do not edit the SQL or the part files. Press `Ctrl+C` if psql is still running (an open transaction is rolled back when the session ends). Copy the exact output, then send it with section 9. Closing the window loses nothing: the Tee-Object files are already saved.

**State after a stop**, so you know what exists:
| Stopped during | What exists | Safe to continue? |
|---|---|---|
| Part 0 | nothing | yes, after the refusal reason is understood |
| Part 1 | nothing (the transaction rolled back) | yes, after review |
| Part 2 | roles; possibly one database | re-running Part 2 is safe and completes it |
| Part 3 or 4 | roles and databases; privileges partly applied | re-running that part is safe (idempotent) once the cause is understood |
| after Part 5 mismatch | everything as created | do not use the databases until reviewed |

**Switching the environment off without deleting anything** (reversible; run as `postgres`, only if you decide to):
```powershell
& $psql @admin -c "ALTER ROLE secureshield_dev_owner NOLOGIN;" -c "ALTER ROLE secureshield_dev_app NOLOGIN;" -c "ALTER ROLE secureshield_test_owner NOLOGIN;"
# optionally also refuse new connections to the databases (data stays intact):
& $psql @admin -c "ALTER DATABASE secureshield_dev ALLOW_CONNECTIONS false;" -c "ALTER DATABASE secureshield_test ALLOW_CONNECTIONS false;"
# to switch back on: ALTER ROLE <name> LOGIN;  ALTER DATABASE <name> ALLOW_CONNECTIONS true;
```
**Wrong password typed?** run `\password <role>` again; nothing else changes. **Part 5 wrong later?** it is read-only; run `Run-Part part5` again at any time.

**Removal** of the databases or roles is deliberately not part of this runbook. It is an administrator decision to be taken only after review and only with explicit approval; do not improvise it. `SecureShieldDB` (the legacy migration source) must never be touched in any case.

**Optional safeguard before Part 1:** if you want a snapshot of the cluster's role definitions, `pg_dumpall --globals-only` writes one, but that file **contains the password hashes of every role on the server**: store it privately, never in the repository, never send it. The `\du+` inventory in 1.8 is usually enough.

---
## 8. What must not happen (quick list)
- psql against anything but `localhost:5432` (never a Neon or Railway host; if you see `neon.tech` anywhere in a prompt or output, stop).
- Any `DROP`, `TRUNCATE`, `DELETE`, `ALTER SYSTEM`, or editing `pg_hba.conf` during this runbook.
- Running Alembic, the backend, integration tests or the migration scripts before Checkpoint 6 is reviewed and a new approval is given.
- Sending passwords, `.env.local`, connection URLs with passwords, or `rolpassword` output.

---
## 9. Evidence to capture and return
Everything is in `C:\SecureShieldActivation\2026-11-15\`. Paste or attach the **text** of these files (they contain no passwords: psql's prompts are hidden and only the reviewed SQL is echoed):
| File | From |
|---|---|
| (typed output) | 1.1 service status, 1.2 empty `PG*` check, 1.3 `psql --version`, `pg_isready` and the identity query, 1.4 free space, 1.5, 1.6 |
| (typed output) | 1.7 the SHA-256 and line count of the SQL |
| `00_inventory_before.txt` | 1.8 |
| `part0.out.txt` ... `part4.out.txt` | each part, with its `exit code` line |
| `part5.out.txt`, `part5_8_dev.txt`, `part5_8_test.txt` | verification |
| `10_has_password.txt` | after the passwords |
| `11_proofs.txt` | P1 to P8 |
| `20_target_dev_static.txt`, `21_target_test_static.txt`, `22_target_dev_real.txt` | target checks |
Also report: the date/time of the run, whether any command needed a retry (and which), and `git status --short backend/docs/database` (the SQL file must still be unmodified).

**Never include:** the passwords, `.env.local`, any URL containing a password, the contents of `pg_authid.rolpassword`, a `pg_dumpall` file, or a transcript of the `\password` session.

---
## 10. Status
**Database activation remains pending your execution and approval.** As of this document no role, database, password, schema or file under `C:\SecureShieldActivation` exists, and nothing has been run against any PostgreSQL server. Stage 1.3 has not been started.
