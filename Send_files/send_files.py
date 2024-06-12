import paramiko
import os

def copy_files(source_path, destination_host, destination_path, username, password):
    # Set up SSH client
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        # Connect to destination ssh server
        ssh_client.connect(hostname=destination_host, username=username, password=password)

        # Create SFTP client
        sftp_client = ssh_client.open_sftp()

        # Change directory to source path
        sftp_client.chdir(source_path)

        # List files in source directory
        files = sftp_client.listdir()

        # Copy each file to destination server
        for file in files:
            remote_file = os.path.join(source_path, file)
            local_file = os.path.join(destination_path, file)
            sftp_client.get(remote_file, local_file)

        # Close SFTP client
        sftp_client.close()

        print("Files copied successfully.")

    except Exception as e:
        print(f"Error: {e}")

    finally:
        # Close SSH client
        ssh_client.close()

if __name__ == "__main__":
    source_path = input("Enter source path: ")
    destination_host = input("Enter destination host: ")
    destination_path = input("Enter destination path: ")
    username = input("Enter host username: ")
    password = input("Enter host password: ")
    copy_files(source_path, destination_host, destination_path, username, password)
