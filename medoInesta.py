import instaloader
import json
import os
from datetime import datetime
import logging
import re
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

def print_header():
    print(Fore.LIGHTBLUE_EX + "="*60)
    print(Fore.LIGHTBLUE_EX + r"""    
███╗   ███╗    ███████╗    ██████╗      ██████╗ 
████╗ ████║    ██╔════╝    ██╔══██╗    ██╔═══██╗
██╔████╔██║    █████╗      ██║  ██║    ██║   ██║
██║╚██╔╝██║    ██╔══╝      ██║  ██║    ██║   ██║
██║ ╚═╝ ██║    ███████╗    ██████╔╝    ╚██████╔╝
╚═╝     ╚═╝    ╚══════╝    ╚═════╝      ╚═════╝     
            Created by Mohammad Salem       
    """)
    print(Fore.LIGHTBLUE_EX + "="*60 + Style.RESET_ALL)

def setup_logging():
    """Configure logging for the application"""
    logging.basicConfig(
        filename='instagram_scraper.log',
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

def validate_username(username):
    """Validate Instagram username format"""
    pattern = r'^[A-Za-z0-9._]+$'
    return bool(re.match(pattern, username))

def get_profile_data(profile):
    """Extract profile data and return as dictionary"""
    try:
        return {
            "Username": profile.username,
            "Full Name": profile.full_name,
            "Followers": profile.followers,
            "Following": profile.followees,
            "Posts": profile.mediacount,
            "Profile Picture URL": profile.profile_pic_url,
            "Verified": profile.is_verified,
            "Private Account": profile.is_private,
            "Bio": profile.biography,
            "External URL": profile.external_url or "None",
            "Business Account": profile.is_business_account,
            "Business Category": profile.business_category_name or "None",
            "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    except Exception as e:
        logging.error(f"Error extracting profile data: {e}")
        raise

def save_to_json(data, filename):
    """Save data to JSON file"""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        logging.info(f"Saved JSON data to {filename}")
    except Exception as e:
        logging.error(f"Error saving JSON: {e}")
        raise

def print_profile(data):
    """Print profile information with formatting"""
    print("\n" + "="*50)
    print("Instagram Profile Information".center(50))
    print("="*50)
    for key, value in data.items():
        print(f"{key:20}: {value}")
    print("="*50)

def main():
    setup_logging()
    L = instaloader.Instaloader()

    print_header()  # Print the header at program start

    while True:
        username = input("\nEnter Instagram username (or 'q' to quit): ").strip()
        
        if username.lower() == 'q':
            print("Exiting program...")
            break

        if not validate_username(username):
            print("Invalid username format! Use letters, numbers, periods, and underscores only.")
            logging.warning(f"Invalid username attempt: {username}")
            continue

        try:
            logging.info(f"Attempting to fetch profile: {username}")
            profile = instaloader.Profile.from_username(L.context, username)
            
            # Get profile data
            data = get_profile_data(profile)
            
            # Print profile
            print_profile(data)
            
            # Create output directory if it doesn't exist
            output_dir = "instagram_profiles"
            os.makedirs(output_dir, exist_ok=True)
            
            # Save to text file
            txt_filename = os.path.join(output_dir, f"{username}_info.txt")
            with open(txt_filename, "w", encoding="utf-8") as f:
                f.write("Instagram Profile Info\n")
                f.write("="*50 + "\n")
                for key, value in data.items():
                    f.write(f"{key}: {value}\n")
            
            # Save to JSON file
            json_filename = os.path.join(output_dir, f"{username}_info.json")
            save_to_json(data, json_filename)
            
            print(f"\n✅ Data saved to:")
            print(f"   - {txt_filename}")
            print(f"   - {json_filename}")
            
            logging.info(f"Successfully processed profile: {username}")
            
        except instaloader.exceptions.ProfileNotExistsException:
            print(f"Error: Profile '{username}' does not exist!")
            logging.error(f"Profile not found: {username}")
        except instaloader.exceptions.ConnectionException:
            print("Error: Connection issue. Please check your internet connection.")
            logging.error("Connection error")
        except instaloader.exceptions.LoginRequiredException:
            print("Error: This profile requires login to view.")
            logging.error(f"Login required for profile: {username}")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            logging.error(f"Unexpected error: {e}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nProgram terminated by user.")
        logging.info("Program terminated by user")
    finally:
        print("\nThank you for using Instagram Profile Scraper!")
