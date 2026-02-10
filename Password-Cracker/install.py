import os
import sys
import subprocess
import shutil
import argparse

def parse_args():
    parser = argparse.ArgumentParser(description="Install Python requirements in a virtual environment")
    parser.add_argument("--venv-dir", default=".venv", help="Virtual environment directory")
    parser.add_argument("--req-file", default="requirements.txt", help="Requirements file")
    parser.add_argument("--clean", action="store_true", help="Delete and recreate the virtual environment")
    parser.add_argument("--upgrade-pip", action="store_true", help="Upgrade pip in the virtual environment")
    return parser.parse_args()

def clean_virtualenv(venv_dir):
    if os.path.exists(venv_dir):
        print(f"🧹 Removing existing virtual environment at {venv_dir}")
        shutil.rmtree(venv_dir)

def is_venv_broken(venv_dir):
    pip_path = get_venv_executable(venv_dir, "pip")
    return not os.path.exists(pip_path)

def create_virtualenv(venv_dir):
    subprocess.check_call([sys.executable, "-m", "venv", venv_dir])
    print(f"✅ Created virtual environment at {venv_dir}")
    hide_venv_folder(venv_dir)

def get_venv_executable(venv_dir, executable):
    if os.name == "nt":
        return os.path.join(venv_dir, "Scripts", f"{executable}.exe")
    return os.path.join(venv_dir, "bin", executable)

def install_requirements(venv_dir, req_file, upgrade_pip):
    pip_path = get_venv_executable(venv_dir, "pip")
    if not os.path.exists(req_file):
        print(f"❌ {req_file} not found.")
        sys.exit(1)
    try:
        if upgrade_pip:
            subprocess.check_call([pip_path, "install", "--upgrade", "pip"])
            print("⬆️ Upgraded pip")
        subprocess.check_call([pip_path, "install", "-r", req_file])
        print(f"✅ Installed packages from {req_file}")
    except subprocess.CalledProcessError as e:
        print(f"❌ pip install failed with exit code {e.returncode}")
        sys.exit(e.returncode)

def hide_venv_folder(venv_dir):
    if os.name == "nt":
        abs_path = os.path.abspath(venv_dir)
        if os.path.exists(abs_path):
            try:
                result = subprocess.run(["attrib", "+h", abs_path], capture_output=True, text=True)
                if result.returncode == 0:
                    print(f"🙈 Successfully hid {abs_path}")
                else:
                    print(f"⚠️ Failed to hide {abs_path}\n{result.stderr}")
            except Exception as e:
                print(f"❌ Error hiding {abs_path}: {e}")

def main():
    args = parse_args()
    venv_dir = args.venv_dir
    req_file = args.req_file

    if args.clean or is_venv_broken(venv_dir):
        clean_virtualenv(venv_dir)

    if not os.path.exists(venv_dir):
        create_virtualenv(venv_dir)

    install_requirements(venv_dir, req_file, args.upgrade_pip)

    print("\n🚀 Done. To activate the virtual environment:")
    if os.name == "nt":
        print(f"   {venv_dir}\\Scripts\\activate")
    else:
        print(f"   source {venv_dir}/bin/activate")

if __name__ == "__main__":
    main()
