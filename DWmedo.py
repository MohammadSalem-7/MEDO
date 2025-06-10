import os
import subprocess
from yt_dlp import YoutubeDL

# لون سماوي للواجهة
CYAN = "\033[96m"
RESET = "\033[0m"

def print_header():
    print("="*60)
    print(r"""    
███╗   ███╗    ███████╗    ██████╗      ██████╗ 
████╗ ████║    ██╔════╝    ██╔══██╗    ██╔═══██╗
██╔████╔██║    █████╗      ██║  ██║    ██║   ██║
██║╚██╔╝██║    ██╔══╝      ██║  ██║    ██║   ██║
██║ ╚═╝ ██║    ███████╗    ██████╔╝    ╚██████╔╝
╚═╝     ╚═╝    ╚══════╝    ╚═════╝      ╚═════╝     
            Created by Mohammad Salem       
    """)
    print("="*60)

def get_download_path():
    return "/data/data/com.termux/files/home/storage/downloads"

def get_video_info(url):
    with YoutubeDL({'quiet': True}) as ydl:
        info = ydl.extract_info(url, download=False)
        formats = info.get('formats', [info])
        video_formats = [f for f in formats if f.get('vcodec') != 'none' and f.get('acodec') != 'none']
        return video_formats

def list_quality_options(formats):
    print(CYAN + "\nAvailable Qualities:\n" + RESET)
    choices = {}
    for i, f in enumerate(formats):
        res = f.get('format_note') or f.get('height', 'unknown')
        ext = f.get('ext')
        size = f.get('filesize', 0)
        size_mb = f"{size / (1024*1024):.2f}MB" if size else "Unknown"
        print(f"[{i+1}] {res} - {ext.upper()} - {size_mb}")
        choices[i+1] = f['format_id']
    return choices

def download_video(url, format_id, path):
    ydl_opts = {
        'format': format_id,
        'outtmpl': f'{path}/%(title)s.%(ext)s',
        'merge_output_format': 'mp4',
        'ffmpeg_location': 'ffmpeg',
    }
    with YoutubeDL(ydl_opts) as ydl:
        ydl.download([url])

def download_audio(url, path):
    ydl_opts = {
        'format': 'bestaudio/best',
        'outtmpl': f'{path}/%(title)s.%(ext)s',
        'postprocessors': [{
            'key': 'FFmpegExtractAudio',
            'preferredcodec': 'mp3',
            'preferredquality': '192',
        }],
        'ffmpeg_location': 'ffmpeg',
    }
    with YoutubeDL(ydl_opts) as ydl:
        ydl.download([url])

def main():
    print_header()
    url = input(CYAN + "[+] Enter YouTube Video URL: " + RESET).strip()
    print(CYAN + "[1] Download Video\n[2] Download Audio Only (MP3)" + RESET)
    choice = input("Select (1 or 2): ").strip()

    download_path = get_download_path()

    if choice == "1":
        formats = get_video_info(url)
        options = list_quality_options(formats)
        selected = int(input("\nSelect Quality Number: "))
        format_id = options.get(selected)
        if format_id:
            print(CYAN + "\n[+] Downloading video..." + RESET)
            download_video(url, format_id, download_path)
        else:
            print("Invalid selection.")
    elif choice == "2":
        print(CYAN + "\n[+] Downloading audio..." + RESET)
        download_audio(url, download_path)
    else:
        print("Invalid option.")

    print(CYAN + "\n[✓] Done. File saved in Downloads." + RESET)

if __name__ == "__main__":
    main()
