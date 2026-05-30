import os
import sys
import subprocess
import venv
import platform

def run_command(command, shell=False):
    try:
        subprocess.check_call(command, shell=shell)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {command}. Error: {e}")
        return False

def setup():
    # 1. Determine environment paths
    venv_dir = os.path.join(os.path.dirname(__file__), ".venv")

    if platform.system() == "Windows":
        python_exe = os.path.join(venv_dir, "Scripts", "python.exe")
        pip_exe = os.path.join(venv_dir, "Scripts", "pip.exe")
    else:
        python_exe = os.path.join(venv_dir, "bin", "python")
        pip_exe = os.path.join(venv_dir, "bin", "pip")

    # 2. Create virtual environment if it doesn't exist
    if not os.path.exists(venv_dir):
        print(f"Creating virtual environment in {venv_dir}...")
        venv.create(venv_dir, with_pip=True)

    # 3. Install/Update requirements
    print("Checking/Installing dependencies...")
    requirements_file = os.path.join(os.path.dirname(__file__), "requirements.txt")
    if os.path.exists(requirements_file):
        if not run_command([pip_exe, "install", "-r", requirements_file]):
            print("Failed to install requirements.")
            return None
    else:
        print("requirements.txt not found. Skipping dependency installation.")

    return python_exe

def main():
    print("--- SNI-Spoofing Auto Starter ---")

    # Check for root on Linux
    if platform.system() == "Linux" and os.geteuid() != 0:
        print("Error: This script must be run as root (sudo) on Linux to intercept packets.")
        sys.exit(1)

    python_exe = setup()
    if not python_exe:
        print("Setup failed.")
        sys.exit(1)

    print("Launching SNI-Spoofing...")
    main_script = os.path.join(os.path.dirname(__file__), "main.py")

    try:
        # Use subprocess.run to keep the process interactive
        subprocess.run([python_exe, main_script])
    except KeyboardInterrupt:
        print("\nStopping...")

if __name__ == "__main__":
    main()
