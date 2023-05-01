import sys
import shutil
import subprocess
# create by ketcup
dependencies = [
    "openssl",
    "curl",
    "waybackurls",
    "whatweb",
    "wafw00f",
    "aquatone",
    "sqlmap",
    "dirb",
    "ffuf",
    "jq",
    "nmap",
]

python_libraries = [
    "colorama",
    "requests",
]

def check_dependency(dependency):
    return shutil.which(dependency) is not None

def check_python_library(library):
    try:
        subprocess.run(
            [sys.executable, "-c", f"import {library}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            check=True,
        )
        return True
    except (subprocess.CalledProcessError, ImportError):
        return False

def main():
    print("Checking dependencies...")

    missing_dependencies = []
    for dependency in dependencies:
        if not check_dependency(dependency):
            missing_dependencies.append(dependency)

    missing_python_libraries = []
    for library in python_libraries:
        if not check_python_library(library):
            missing_python_libraries.append(library)

    if not missing_dependencies and not missing_python_libraries:
        print("All dependencies are installed.")
    else:
        if missing_dependencies:
            print("Some dependencies are missing:")
            for dependency in missing_dependencies:
                print(f"  - {dependency}")

        if missing_python_libraries:
            print("\nSome Python libraries are missing:")
            for library in missing_python_libraries:
                print(f"  - {library}")
            print("\nTo install missing Python libraries, run the following command:")
            print(f"  pip install {' '.join(missing_python_libraries)}")

        print("\nPlease install the missing dependencies and Python libraries.")

if __name__ == "__main__":
    main()
