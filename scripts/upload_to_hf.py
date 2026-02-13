
import os
import sys
from huggingface_hub import HfApi, login

def upload_dataset(repo_id, folder_path, token=None):
    if token:
        login(token=token, add_to_git_credential=True)
    
    api = HfApi()
    
    # Check if repo exists, if not create it
    try:
        api.repo_info(repo_id=repo_id, repo_type="dataset")
        print(f"Repository {repo_id} already exists.")
    except Exception as e:
        print(f"Repository {repo_id} does not exist. Creating it...")
        api.create_repo(repo_id=repo_id, repo_type="dataset", exist_ok=True)

    print(f"Uploading folder {folder_path} to {repo_id}...")
    api.upload_folder(
        folder_path=folder_path,
        repo_id=repo_id,
        repo_type="dataset",
    )
    print("Upload complete!")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 upload_to_hf.py <repo_id> <folder_path> [token]")
        sys.exit(1)

    repo_id = sys.argv[1]
    folder_path = sys.argv[2]
    token = sys.argv[3] if len(sys.argv) > 3 else None

    if not token and not os.environ.get("HF_TOKEN"):
         # Try to see if we are logged in
         try:
             whoami = HfApi().whoami()
             print(f"Logged in as {whoami['name']}")
         except:
             print("Error: No token provided and not logged in. Please provide a token as the 3rd argument or set HF_TOKEN environment variable.")
             sys.exit(1)
    
    if os.environ.get("HF_TOKEN") and not token:
        token = os.environ.get("HF_TOKEN")

    upload_dataset(repo_id, folder_path, token)
