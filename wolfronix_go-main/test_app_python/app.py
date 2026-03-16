import asyncio
import sys
import os
import json
import httpx
from colorama import init, Fore, Style
from getpass import getpass

# Import Wolfronix SDK
# Assuming it's installed via pip or accessible in PYTHONPATH
try:
    from wolfronix import Wolfronix, WolfronixConfig
    from wolfronix.errors import WolfronixError, AuthenticationError
except ImportError:
    print(f"{Fore.RED}Error: wolfronix SDK not found.{Style.RESET_ALL}")
    print(f"Make sure to install it: pip install -e ../sdk/python")
    sys.exit(1)

init(autoreset=True)

# Configuration defaults
DEFAULT_BASE_URL = "https://49.206.202.13:9443/"
DEFAULT_CLIENT_ID = "wolfronix_client_1"
DEFAULT_WOLFRONIX_KEY = "685777a685a8b7fe3aee6c8c54a88698fa28b8dc14faaae495091cdc8520cbaf"

# For relaying chat messages, matching the Node.js test app
RELAY_URL = "http://localhost:3000"

async def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header(title):
    print(f"\n{Fore.CYAN}{'=' * 60}")
    print(f"{Fore.CYAN} {title}")
    print(f"{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}\n")

async def chat_poll_loop(wfx: Wolfronix, user_id: str):
    """Background task to poll for messages from the relay."""
    print(f"{Fore.LIGHTBLACK_EX}[Chat Poll] Started listening for messages...{Style.RESET_ALL}")
    last_printed_msg_id = None
    
    async with httpx.AsyncClient() as client:
        while True:
            if not wfx.is_authenticated():
                break

            try:
                # Poll the relay server
                res = await client.get(f"{RELAY_URL}/api/chat/messages", params={"userId": user_id})
                
                if res.status_code == 200:
                    data = res.json()
                    messages = data.get("messages", [])
                    
                    for msg in messages:
                        sender = msg.get("from", "Unknown")
                        packet = msg.get("packet", "")
                        
                        try:
                            # Decrypt the zero-knowledge message
                            decrypted_text = await wfx.decrypt_message(packet)
                            print(f"\n{Fore.YELLOW}[NEW MESSAGE] From: {sender}{Style.RESET_ALL}")
                            print(f"{Fore.WHITE}> {decrypted_text}{Style.RESET_ALL}")
                            # Print a new prompt line since we interrupted the console
                            print(f"{Fore.GREEN}Action (upload/list/download/chat/logout): {Style.RESET_ALL}", end="", flush=True)
                        except Exception as decrypt_err:
                            print(f"\n{Fore.RED}[Chat Poll] Failed to decrypt message from {sender}: {decrypt_err}{Style.RESET_ALL}")
                            print(f"{Fore.GREEN}Action (upload/list/download/chat/logout): {Style.RESET_ALL}", end="", flush=True)

            except httpx.RequestError:
                # Relay is offline, silently fail like the JS client
                pass
            except Exception as e:
                # Other errors
                pass

            await asyncio.sleep(2.0)

async def main():
    await clear_screen()
    print_header("Wolfronix Python SDK Test App")

    # Initialize SDK
    wfx = Wolfronix(WolfronixConfig(
        base_url=DEFAULT_BASE_URL,
        client_id=DEFAULT_CLIENT_ID,
        wolfronix_key=DEFAULT_WOLFRONIX_KEY,
        insecure=True, # allow self-signed local certs
    ))

    print(f"Connecting to {DEFAULT_BASE_URL}...")
    try:
        ok = await wfx.health_check()
        if ok:
            print(f"{Fore.GREEN}✓ Connected to Wolfronix Server{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}✗ Server connection failed or degraded{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}✗ Failed to initialize SDK: {e}{Style.RESET_ALL}")
        return

    user_email = None
    poll_task = None

    # --- Authentication Loop ---
    while not wfx.is_authenticated():
        print("\n1. Login")
        print("2. Register")
        print("3. Exit")
        choice = input("Select an option: ").strip()

        if choice == "3":
            return
        elif choice == "2":
            email = input("Email: ").strip()
            password = getpass("Password: ")
            try:
                res = await wfx.register(email, password, enable_recovery=True)
                print(f"{Fore.GREEN}✓ Registered successfully!{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}IMPORTANT: Save your recovery phrase:{Style.RESET_ALL}")
                phrase = getattr(res, 'recovery_phrase', None) or getattr(res, 'recoveryWords', None)
                print(f"{Fore.WHITE}{phrase}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}Register failed: {e}{Style.RESET_ALL}")
        elif choice == "1":
            email = input("Email: ").strip()
            password = getpass("Password: ")
            try:
                print("Logging in...")
                await wfx.login(email, password)
                user_email = wfx.get_user_id()
                print(f"{Fore.GREEN}✓ Logged in as {user_email}{Style.RESET_ALL}")
                
                # Start poll loop
                poll_task = asyncio.create_task(chat_poll_loop(wfx, user_email))
            except Exception as e:
                print(f"{Fore.RED}Login failed: {e}{Style.RESET_ALL}")

    # --- Main App Loop ---
    while wfx.is_authenticated():
        print_header("Main Menu")
        action = input(f"{Fore.GREEN}Action (upload/list/download/chat/logout): {Style.RESET_ALL}").strip().lower()

        if action == "logout":
            wfx.logout()
            print("Logged out.")
            if poll_task:
                poll_task.cancel()
            break

        elif action == "upload":
            filepath = input("Enter file path to upload: ").strip()
            if not os.path.exists(filepath):
                print(f"{Fore.RED}File not found.{Style.RESET_ALL}")
                continue
            
            filename = os.path.basename(filepath)
            filesize = os.path.getsize(filepath)
            
            try:
                with open(filepath, "rb") as f:
                    file_data = f.read()

                print(f"Encrypting and uploading '{filename}' ({filesize} bytes)...")
                
                res = await wfx.encrypt(file_data, filename=filename)
                
                print(f"{Fore.GREEN}✓ File uploaded successfully!{Style.RESET_ALL}")
                print(f"File ID: {res.get('file_id')}")
            except Exception as e:
                print(f"{Fore.RED}Upload failed: {e}{Style.RESET_ALL}")

        elif action == "list":
            try:
                print("Fetching vault...")
                files_res = await wfx.list_files()
                files = files_res.get("files", [])
                if not files:
                    print("Vault is empty.")
                else:
                    print(f"\n{Fore.CYAN}--- Your Vault ---{Style.RESET_ALL}")
                    for idx, f in enumerate(files, 1):
                        print(f"[{idx}] {f.get('original_name')} (ID: {f.get('file_id')})")
            except Exception as e:
                print(f"{Fore.RED}List files failed: {e}{Style.RESET_ALL}")

        elif action == "download":
            file_id = input("Enter File ID to download: ").strip()
            dest_path = input("Enter destination filename/path (or leave blank to save in current dir as downloaded_file): ").strip()
            if not dest_path:
                dest_path = "downloaded_file"
                
            try:
                print(f"Decrypting file {file_id}...")
                decrypted_data = await wfx.decrypt(file_id)
                
                with open(dest_path, "wb") as f:
                    f.write(decrypted_data)
                    
                print(f"{Fore.GREEN}✓ File downloaded and decrypted to '{dest_path}'{Style.RESET_ALL}")
            except FileNotFoundError:
                print(f"{Fore.RED}File ID not found on server.{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}Download failed: {e}{Style.RESET_ALL}")

        elif action == "chat":
            recipient = input("Enter recipient exact Email/UserID: ").strip()
            if not recipient:
                continue
            
            msg = input("Enter message: ").strip()
            if not msg:
                continue
                
            try:
                print(f"Encrypting message for {recipient}...")
                # 1. Zero-knowledge encryption of the message for the recipient
                encrypted_packet = await wfx.encrypt_message(msg, recipient)
                
                # 2. Send the encrypted packet via our insecure relay server
                async with httpx.AsyncClient() as client:
                    res = await client.post(
                        f"{RELAY_URL}/api/chat/send",
                        json={
                            "to": recipient,
                            "from": user_email,
                            "packet": encrypted_packet
                        }
                    )
                    
                    if res.status_code == 200:
                        print(f"{Fore.GREEN}✓ Message sent securely.{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.RED}Relay server rejected message: {res.text}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}Chat send failed: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)
