#!/usr/bin/env python3
import argparse, os, shutil, subprocess, tarfile, tempfile, time
from pathlib import Path

def make_files(root, count=100, size=256):
    root.mkdir(parents=True, exist_ok=True)
    payload = (b"legitimate-baseline-data-" * ((size // 25) + 1))[:size]
    for i in range(count):
        p = root / f"file-{i:04d}.txt"
        p.write_bytes(payload)

def editing():
    with tempfile.TemporaryDirectory(prefix="shield-edit-") as d:
        p = Path(d) / "document.txt"
        p.write_text("initial\n")
        for i in range(80):
            with p.open("a") as f: f.write(f"edit {i}\n")
            time.sleep(0.04)
        time.sleep(3)

def archive():
    with tempfile.TemporaryDirectory(prefix="shield-archive-") as d:
        root=Path(d); src=root/"src"; dst=root/"dst"; make_files(src, 120)
        archive_path=root/"archive.tar"
        with tarfile.open(archive_path, "w") as tf: tf.add(src, arcname="src")
        dst.mkdir();
        with tarfile.open(archive_path) as tf: tf.extractall(dst)
        time.sleep(3)

def copy_workload(kind):
    with tempfile.TemporaryDirectory(prefix=f"shield-{kind}-") as d:
        root=Path(d); src=root/"src"; dst=root/"dst"; make_files(src, 160)
        dst.mkdir();
        for p in src.iterdir(): shutil.copy2(p, dst/p.name)
        time.sleep(3)

def git_checkout():
    with tempfile.TemporaryDirectory(prefix="shield-git-") as d:
        root=Path(d); repo=root/"repo"; repo.mkdir(); subprocess.run(["git","init","-q",str(repo)],check=True)
        for i in range(100): (repo/f"source-{i:04d}.txt").write_text(f"v1-{i}\n")
        subprocess.run(["git","-C",str(repo),"add","."],check=True); subprocess.run(["git","-C",str(repo),"-c","user.name=Lab","-c","user.email=lab@example.invalid","commit","-q","-m","initial"],check=True)
        subprocess.run(["git","-C",str(repo),"checkout","-q","-b","second"],check=True)
        for i in range(100): (repo/f"source-{i:04d}.txt").write_text(f"v2-{i}\n")
        subprocess.run(["git","-C",str(repo),"add","."],check=True); subprocess.run(["git","-C",str(repo),"-c","user.name=Lab","-c","user.email=lab@example.invalid","commit","-q","-m","second"],check=True)
        subprocess.run(["git","-C",str(repo),"checkout","-q","master"],check=True); time.sleep(3)

def compile_workload():
    with tempfile.TemporaryDirectory(prefix="shield-build-") as d:
        root=Path(d); makefile=root/"Makefile"; lines=[]
        for i in range(25):
            c=root/f"unit-{i:02d}.c"; c.write_text("int f_%d(void){return %d;}\n"%(i,i)); lines.append(f"unit-{i:02d}.o:")
            lines.append(f"\tgcc -c unit-{i:02d}.c -o unit-{i:02d}.o")
        makefile.write_text("\n".join(lines)+"\n")
        subprocess.run(["make","-C",str(root),"-j2"],check=True); time.sleep(3)

def create_workload():
    with tempfile.TemporaryDirectory(prefix="shield-create-") as d:
        root=Path(d); make_files(root, 240, 512); time.sleep(3)

def idle(): time.sleep(7)

def main():
    p=argparse.ArgumentParser(); p.add_argument("workload",choices=["idle","editing","archive","copy","git-checkout","compile","backup","create"]); a=p.parse_args()
    {"idle":idle,"editing":editing,"archive":archive,"copy":lambda:copy_workload("copy"),"git-checkout":git_checkout,"compile":compile_workload,"backup":lambda:copy_workload("backup"),"create":create_workload}[a.workload]()
if __name__ == "__main__": main()