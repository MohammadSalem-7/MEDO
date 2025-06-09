import instaloader

# Create Instaloader instance
L = instaloader.Instaloader()

# Ask for Instagram username
username = input("Enter the Instagram username: ")

try:
    # Load profile
    profile = instaloader.Profile.from_username(L.context, username)

    # Gather data
    data = {
        "Username": profile.username,
        "Full Name": profile.full_name,
        "Followers": profile.followers,
        "Following": profile.followees,
        "Posts": profile.mediacount,
        "Profile Picture URL": profile.profile_pic_url,
        "Verified": "Yes" if profile.is_verified else "No",
        "Private Account": "Yes" if profile.is_private else "No",
        "Bio": profile.biography,
        "External URL": profile.external_url if profile.external_url else "None"
    }

    # Print to screen
    print("\n--- Instagram Profile Info ---")
    for key, value in data.items():
        print(f"{key}: {value}")

    # Save to file
    filename = f"{username}_info.txt"
    with open(filename, "w", encoding="utf-8") as file:
        file.write("Instagram Profile Info\n")
        file.write("=======================\n")
        for key, value in data.items():
            file.write(f"{key}: {value}\n")

    print(f"\n✅ Data saved to {filename}")

except Exception as e:
    print("\nAn error occurred!")
    print(f"Details: {e}")

# Pause before closing
input("\nPress Enter to exit...")
