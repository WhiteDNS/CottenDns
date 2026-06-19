import os
import subprocess
import shutil
import time
from pathlib import Path

def get_version():
    try:
        # Try to get short commit hash
        commit = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], text=True).strip()
        return f"local-{commit}"
    except Exception:
        return "local-dev"

def resolve_c_compiler(env):
    try:
        cc = subprocess.check_output(["go", "env", "CC"], env=env, text=True).strip()
    except Exception:
        return None

    if not cc:
        return None

    cc_bin = cc.split()[0].strip('"')
    if shutil.which(cc_bin) is None:
        return None

    return cc

def build(goos, goarch, goarm, component, output_name, require_cgo=False):
    print(f"Building {component} for {goos}/{goarch}...")
    
    env = os.environ.copy()
    env["GOOS"] = goos
    env["GOARCH"] = goarch
    if goarm:
        env["GOARM"] = goarm
    env["CGO_ENABLED"] = "1" if require_cgo else "0"

    if require_cgo:
        cc = resolve_c_compiler(env)
        if not cc:
            print(
                f"Skipping {component} for {goos}/{goarch}: "
                "cgo toolchain not found (set CC to an Android cross-compiler)."
            )
            return "skipped"
    
    version = get_version()
    ldflags = f"-s -w -X cottenpickdns-go/internal/version.BuildVersion={version}"
    
    cmd = [
        "go", "build",
        "-trimpath",
        "-ldflags", ldflags,
        "-o", output_name,
        f"./cmd/{component}"
    ]
    
    try:
        subprocess.run(cmd, env=env, check=True)
        print(f"Successfully built: {output_name}")
        return "ok"
    except subprocess.CalledProcessError as e:
        print(f"Failed to build {component} for {goos}/{goarch}: {e}")
        return "failed"

def main():
    dist_dir = Path("dist")
    if not dist_dir.exists():
        dist_dir.mkdir()
        
    targets = [
        {"os": "linux", "arch": "amd64", "ext": "", "platform": "Linux"},
        {"os": "windows", "arch": "amd64", "ext": ".exe", "platform": "Windows"},
        {"os": "android", "arch": "arm64", "ext": "", "platform": "Termux"},
        {"os": "android", "arch": "arm", "goarm": "7", "ext": "", "platform": "Termux", "require_cgo": True},
    ]

    failed = []
    skipped = []
    
    for t in targets:
        for component in ["client", "server"]:
            output_name = f"dist/CottenpickDNS_{component.capitalize()}_{t['platform']}_{t['arch']}{t['ext']}"
            result = build(
                t["os"],
                t["arch"],
                t.get("goarm"),
                component,
                output_name,
                t.get("require_cgo", False),
            )
            if result == "failed":
                failed.append(f"{component}:{t['os']}/{t['arch']}")
            elif result == "skipped":
                skipped.append(f"{component}:{t['os']}/{t['arch']}")

    if failed:
        print("Build failed for:", ", ".join(failed))
        exit(1)
            
    print("Copying config files...")
    shutil.copy("client_config.toml.simple", dist_dir / "client_config.toml")
    shutil.copy("server_config.toml.simple", dist_dir / "server_config.toml")

    print("Copying README files...")
    if Path("README.MD").exists():
        shutil.copy("README.MD", dist_dir / "README.MD")
    if Path("README_FA.MD").exists():
        shutil.copy("README_FA.MD", dist_dir / "README_FA.MD")
        
    if skipped:
        print("Skipped targets:", ", ".join(skipped))

    print("Build complete.")

if __name__ == "__main__":
    main()
