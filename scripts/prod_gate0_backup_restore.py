"""One-shot, read-only Production export and isolated local restore.

The workflow publishes fixed status messages only. Raw tool output stays in
runner memory and is deliberately discarded on failure.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
from urllib.parse import parse_qs, quote, unquote, urlparse

REF = "ebwtainwlgruoglyckui"
EXCLUDED = ("storage.buckets_vectors", "storage.vector_indexes")
WORK = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "adp-production-gate0"
RESTORE = WORK / "restore-check"
BACKUP = WORK / "backup"
LOCAL_URL = "postgresql://postgres:postgres@127.0.0.1:54322/postgres"


class GateError(Exception):
    pass


def run(stage, *args, cwd=None, env=None):
    try:
        result = subprocess.run(args, cwd=cwd, env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, check=False, timeout=300)
    except FileNotFoundError:
        raise GateError("CLIENT_UNAVAILABLE") from None
    except subprocess.TimeoutExpired:
        raise GateError("CONNECTION_TIMEOUT" if stage == "SOURCE_IDENTITY_FAILED" else stage) from None
    if result.returncode:
        if stage == "SOURCE_IDENTITY_FAILED":
            detail = result.stderr.decode("utf-8", errors="replace").lower()
            for phrase, fixed in (("password authentication failed", "DATABASE_PASSWORD_REJECTED"),
                                  ("tenant or user not found", "POOLER_USER_REJECTED"),
                                  ("could not translate host name", "POOLER_DNS_FAILED"),
                                  ("connection timed out", "CONNECTION_TIMEOUT"),
                                  ("network is unreachable", "POOLER_NETWORK_FAILED"),
                                  ("no route to host", "POOLER_NETWORK_FAILED"),
                                  ("ssl", "POOLER_TLS_FAILED")):
                if phrase in detail:
                    raise GateError(fixed)
        raise GateError(stage)
    return result.stdout.decode("utf-8", errors="replace")


def verify_connection_url(value):
    if not value:
        raise GateError("MISSING_DATABASE_SECRET")
    try:
        parsed = urlparse(value)
        if (parsed.scheme not in ("postgres", "postgresql") or
                parsed.hostname is None or
                not parsed.hostname.endswith(".pooler.supabase.com") or
                parsed.port != 5432 or parsed.path != "/postgres" or
                unquote(parsed.username or "") != f"postgres.{REF}" or
                not parsed.password or
                parse_qs(parsed.query).get("options") != ["-c jit=true"] or
                parse_qs(parsed.query).get("sslmode") not in
                (["require"], ["verify-ca"], ["verify-full"])):
            raise ValueError("unexpected connection")
    except (ValueError, TypeError):
        raise GateError("INVALID_PRODUCTION_CONNECTION") from None


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def fingerprint(db_url, stage):
    # The SQL returns table names, counts and hashes of rows. It never prints
    # records, and its captured result is written only into the private archive.
    query = r"""
SELECT format(
  'SELECT %L, count(*), coalesce(md5(string_agg(to_jsonb(t)::text, '''' ORDER BY to_jsonb(t)::text)), md5('''')) FROM %I.%I t;',
  schemaname || '.' || tablename, schemaname, tablename)
FROM pg_tables
WHERE schemaname IN ('public', 'auth', 'storage')
  AND NOT (schemaname = 'storage' AND tablename IN ('buckets_vectors', 'vector_indexes'))
ORDER BY schemaname, tablename
\gexec
"""
    sql_file = WORK / "fingerprint.sql"
    sql_file.write_text(query)
    rows = run(stage, "psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1",
               "--dbname", db_url, "--file", str(sql_file))
    columns = run(stage, "psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1",
                  "--dbname", db_url, "--command", """
SELECT md5(coalesce(string_agg(
    table_schema || '.' || table_name || '.' || column_name || ':' ||
    data_type || ':' || is_nullable, '|' ORDER BY table_schema, table_name, ordinal_position), ''))
FROM information_schema.columns
WHERE table_schema IN ('public', 'auth', 'storage');
""").strip()
    return rows, columns


def public_security_fingerprint(db_url, stage):
    return run(stage, "psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1",
               "--dbname", db_url, "--command", """
SELECT md5(coalesce(string_agg(item, '|' ORDER BY item), ''))
FROM (
  SELECT 'function:' || p.oid::regprocedure::text || ':' ||
         pg_get_functiondef(p.oid) AS item
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname = 'public'
  UNION ALL
  SELECT 'grant:' || table_schema || '.' || table_name || ':' ||
         grantee || ':' || privilege_type AS item
  FROM information_schema.table_privileges
  WHERE table_schema = 'public'
) entries;
""").strip()


def main():
    token = os.environ.get("PROD_TEMP_TOKEN", "")
    if not token or not re.fullmatch(r"sbp_[A-Za-z0-9_-]+", token):
        raise GateError("MISSING_OR_INVALID_TEMP_TOKEN")
    url = (
        f"postgresql://postgres.{REF}:{quote(token, safe='')}"
        "@aws-0-us-east-1.pooler.supabase.com:5432/postgres"
        "?sslmode=require&options=-c%20jit%3Dtrue"
    )
    verify_connection_url(url)
    if WORK.exists():
        raise GateError("WORKSPACE_EXISTS")
    BACKUP.mkdir(parents=True)
    source_time = run("SOURCE_IDENTITY_FAILED", "psql", "-X", "-qAt",
                      "-v", "ON_ERROR_STOP=1", "--dbname", url,
                      "--command", "SELECT clock_timestamp()::text, current_database(), current_user;").strip()
    if "|postgres|" not in source_time or not source_time:
        raise GateError("SOURCE_IDENTITY_MISMATCH")
    ready = run("RELEASE_CHECK_FAILED", "psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1",
                "--dbname", url, "--command", """
SELECT EXISTS (SELECT 1 FROM public.adp_integrity_release
               WHERE singleton = true AND version = 121 AND ready = true);
""").strip()
    if ready != "t":
        raise GateError("RELEASE_NOT_READY")

    source_rows, source_schema = fingerprint(url, "SOURCE_FINGERPRINT_FAILED")
    source_security = public_security_fingerprint(url, "SOURCE_SECURITY_FAILED")
    for filename, flags in (("roles.sql", ("--role-only",)),
                            ("schema.sql", ()),
                            ("data.sql", ("--data-only", "--use-copy",
                                          "-x", EXCLUDED[0], "-x", EXCLUDED[1]))):
        run("EXPORT_FAILED", "supabase", "db", "dump", f"--remote={url}",
            "-f", str(BACKUP / filename), *flags)
        if not (BACKUP / filename).stat().st_size:
            raise GateError("EMPTY_EXPORT")
    required = {"auth.users", "storage.objects"}
    with (BACKUP / "data.sql").open(errors="replace") as dump:
        for line in dump:
            match = re.match(r'^COPY\s+"?(auth|storage)"?\."?([a-z_]+)"?\s*\(', line, re.IGNORECASE)
            if match:
                required.discard(f"{match.group(1).lower()}.{match.group(2).lower()}")
    if required:
        raise GateError("PROTECTED_TABLE_NOT_EXPORTED")
    post_rows, post_schema = fingerprint(url, "POST_EXPORT_FINGERPRINT_FAILED")
    post_security = public_security_fingerprint(url, "POST_EXPORT_SECURITY_FAILED")
    if (source_rows, source_schema, source_security) != (
            post_rows, post_schema, post_security):
        raise GateError("SOURCE_CHANGED_DURING_EXPORT")

    run("LOCAL_INIT_FAILED", "supabase", "init", "--workdir", str(RESTORE))
    run("LOCAL_START_FAILED", "supabase", "db", "start", "--workdir", str(RESTORE))
    run("RESTORE_FAILED", "psql", "-X", "-q", "--single-transaction",
        "-v", "ON_ERROR_STOP=1", "--file", str(BACKUP / "roles.sql"),
        "--file", str(BACKUP / "schema.sql"),
        "--command", "SET session_replication_role = replica",
        "--file", str(BACKUP / "data.sql"), "--dbname", LOCAL_URL)
    restored_rows, restored_schema = fingerprint(LOCAL_URL, "RESTORED_FINGERPRINT_FAILED")
    if source_rows != restored_rows or source_schema != restored_schema:
        raise GateError("RESTORE_FINGERPRINT_MISMATCH")
    restored_security = public_security_fingerprint(LOCAL_URL, "RESTORED_SECURITY_FAILED")
    if source_security != restored_security:
        raise GateError("RESTORE_SECURITY_MISMATCH")

    manifest = {
        "source_project_ref": REF,
        "source_database_identity_and_timestamp": source_time,
        "release_121_ready": True,
        "restore_target": "disposable runner-local Supabase PostgreSQL",
        "restore_verified": True,
        "scope": "roles, default schema, data (Supabase CLI)",
        "excluded_tables": list(EXCLUDED),
        "limitations": ["Storage object bytes, provider settings and external services are not included",
                        "The private GitHub artifact expires seven days after this run"],
        "sha256": {name: digest(BACKUP / name) for name in
                   ("roles.sql", "schema.sql", "data.sql")},
        "schema_fingerprint": source_schema,
        "public_functions_and_grants_fingerprint": source_security,
        "table_fingerprints": source_rows,
    }
    (BACKUP / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    with tarfile.open(WORK / "verified-backup.tar.gz", "w:gz") as archive:
        for path in sorted(BACKUP.iterdir()):
            archive.add(path, arcname=path.name)
    with tarfile.open(WORK / "verified-backup.tar.gz", "r:gz") as archive:
        if sorted(archive.getnames()) != sorted(path.name for path in BACKUP.iterdir()):
            raise GateError("ARCHIVE_INTEGRITY_FAILED")
        for name, expected in manifest["sha256"].items():
            member = archive.extractfile(name)
            if member is None or hashlib.sha256(member.read()).hexdigest() != expected:
                raise GateError("ARCHIVE_INTEGRITY_FAILED")
    print("GATE0_BACKUP_RESTORE_VERIFIED")
    print("GATE0_SOURCE_REF=" + REF)
    print("GATE0_FILES=roles.sql,schema.sql,data.sql,manifest.json")
    print("GATE0_EXCLUSIONS=storage.buckets_vectors,storage.vector_indexes,storage_object_bytes,external_settings")


if __name__ == "__main__":
    try:
        main()
    except GateError as error:
        print("::error::GATE0_" + str(error), file=sys.stderr)
        sys.exit(1)
    except Exception:
        print("::error::GATE0_UNEXPECTED_FAILURE", file=sys.stderr)
        sys.exit(1)
    finally:
        # The hosted runner is disposable. Clear local plaintext even on errors.
        try:
            subprocess.run(("supabase", "stop", "--no-backup", "--workdir", str(RESTORE)),
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        except OSError:
            pass
        if BACKUP.exists():
            shutil.rmtree(BACKUP, ignore_errors=True)
        if RESTORE.exists():
            shutil.rmtree(RESTORE, ignore_errors=True)
