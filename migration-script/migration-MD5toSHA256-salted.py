import subprocess
import hashlib
import secrets

hash_mode = "0"

hash_file = "PASSWORDS.md"

hashcat_output_file = "dehashedpass.txt"

plain_output_file = "plain.txt"

salted_sha256_passwords = "new_passwords.txt"

word_list_file = "/usr/share/wordlists/rockyou.txt"

hashcat_command = f"hashcat -m {hash_mode} {hash_file} {word_list_file} --show -o {hashcat_output_file}"

def generate_salt():
    return secrets.token_hex(16)

def read_hashes(filename):
    with open(filename, 'r') as file:
        return file.read().splitlines()

def read_values(filename):
    with open(filename, 'r') as file:
        lines = file.read().splitlines()
        return {line.split(':')[0]: line.split(':')[1] for line in lines}

def search_values(hashes, values, output_filename):
    with open(output_filename, 'w') as output_file:
        for hash_value in hashes:
            if hash_value in values:
                output_file.write(values[hash_value] + '\n')
            else:
                output_file.write('\n')
def generate_new_passwords():
    with open(plain_output_file, 'r') as infile:
        with open(salted_sha256_passwords, 'w') as outfile:
            for line in infile:
                line = line.strip()
                if line:
                    salt = generate_salt()
                    salted_password = salt+line 
                    hashed_line = hashlib.sha256(salted_password.encode()).hexdigest()
                    outfile.write(hashed_line + '\n')
                else:
                    outfile.write('\n')
try:
    print("Script started")
    subprocess.run(hashcat_command, shell=True, check=True, text=True)
    print("Starting migration")
    hashes = read_hashes(hash_file)
    values = read_values(hashcat_output_file)
    search_values(hashes, values, plain_output_file)
    print("Plain passwords stored")
    generate_new_passwords()
    print("Migration Done")
except subprocess.CalledProcessError as e:
    print(f"Error executing hashcat command: {e}")
except Exception as e:
    print(f"Error executing the migration script: {e}")



