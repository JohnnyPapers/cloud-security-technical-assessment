import subprocess

command = input("Enter command:")

subprocess.run(
    command,
    shell=True
)