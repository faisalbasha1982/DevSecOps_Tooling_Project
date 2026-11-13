"""Test helpers (deliberately unsafe). Excluded by the path excludes (N1)
in config/semgrep.yml: HIGH patterns here must NOT fail the build."""
import subprocess


def run_fixture_command(cmd):
    return subprocess.run(cmd, shell=True, check=False)


def build_query(table):
    return f"SELECT * FROM {table}"


def reset_db(cursor, table):
    cursor.execute(f"DELETE FROM {table}")


def evaluate_fixture(expr):
    return eval(expr)

