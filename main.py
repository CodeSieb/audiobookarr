import os
import asyncio
import sqlite3
import hashlib
import secrets
from datetime import datetime
from typing import List, Optional, Dict, Any
from pathlib import Path
import re
import json

import requests
from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from bs4 import BeautifulSoup
import aiohttp
import aiofiles
from urllib.parse import quote, urljoin
from mutagen.mp3 import MP3
from mutagen.id3 import ID3, TIT2, TPE1, TALB, TRCK

# Models
class SearchResult(BaseModel):
    title: str
    url: str
    author: Optional[str] = None
    series: Optional[str] = None
    cover_image: Optional[str] = None
    description: Optional[str] = None
    published_date: Optional[str] = None

class DownloadRequest(BaseModel):
    title: str
    url: str
    author: Optional[str] = None
    series: Optional[str] = None

class QueueItem(BaseModel):
    id: int
    title: str
    author: Optional[str]
    series: Optional[str]
    status: str  # waiting, downloading, completed, failed
    progress: float
    created_at: str
    completed_at: Optional[str] = None
    error_message: Optional[str] = None

class LoginRequest(BaseModel):
    password: str

class PasswordChangeRequest(BaseModel):
    old_password: str
    new_password: str

class Settings(BaseModel):
    google_books_api_key: Optional[str] = None
    audiobookshelf_url: Optional[str] = None
    audiobookshelf_token: Optional[str] = None
    auto_refresh: bool = True

# Database setup
def init_db():
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Queue table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            url TEXT NOT NULL,
            author TEXT,
            series TEXT,
            status TEXT DEFAULT 'waiting',
            progress REAL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP,
            error_message TEXT
        )
    ''')
    
    # Settings table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    ''')
    
    conn.commit()
    conn.close()

# Authentication
security = HTTPBearer(auto_error=False)

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password: str, password_hash: str) -> bool:
    return hash_password(password) == password_hash

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE password_hash = ?", (credentials.credentials,))
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    return user[0]

# FastAPI app
app = FastAPI(title="TokyBook Downloader")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global variables - MUST BE HERE AT MODULE LEVEL
download_queue = asyncio.Queue()
current_download = None
websocket_connections = set()

# Settings management
def get_setting(key: str) -> Optional[str]:
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM settings WHERE key = ?", (key,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None

def set_setting(key: str, value: str):
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
    conn.commit()
    conn.close()

# Google Books API integration
async def enrich_with_google_books(title: str, author: str = None) -> Dict[str, Any]:
    api_key = get_setting('google_books_api_key')
    if not api_key:
        return {}
    
    query = f"intitle:{title}"
    if author:
        query += f" inauthor:{author}"
    
    url = f"https://www.googleapis.com/books/v1/volumes?q={quote(query)}&key={api_key}"
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get('items'):
                        book = data['items'][0]['volumeInfo']
                        return {
                            'author': ', '.join(book.get('authors', [])),
                            'description': book.get('description', ''),
                            'cover_image': book.get('imageLinks', {}).get('thumbnail', ''),
                            'published_date': book.get('publishedDate', ''),
                            'series': extract_series_from_title(book.get('title', ''))
                        }
    except Exception as e:
        print(f"Google Books API error: {e}")
    
    return {}

def extract_series_from_title(title: str) -> Optional[str]:
    # Simple series extraction logic
    patterns = [
        r'(.+?)\s+(?:Book|Vol\.?|Volume)\s+\d+',
        r'(.+?)\s+#\d+',
        r'(.+?)\s+\d+$'
    ]
    
    for pattern in patterns:
        match = re.match(pattern, title, re.IGNORECASE)
        if match:
            return match.group(1).strip()
    
    return None

# TokyBook scraping
async def search_tokybook(query: str) -> List[SearchResult]:
    search_url = f"https://tokybook.com/?s={quote(query)}"
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(search_url, timeout=10) as response:
                if response.status != 200:
                    return []
                
                html = await response.text()
                soup = BeautifulSoup(html, 'html.parser')
                
                # Check for no results
                not_found = soup.find("h1", {"class": "entry-title"})
                if not_found and "Nothing Found" in not_found.get_text():
                    return []
                
                results = []
                entries = soup.find_all("h2", {"class": "entry-title"})
                
                for entry in entries:
                    link = entry.find("a")
                    if link:
                        title = link.get_text().strip()
                        url = link.get("href")
                        
                        # Enrich with Google Books data
                        google_data = await enrich_with_google_books(title)
                        
                        results.append(SearchResult(
                            title=title,
                            url=url,
                            **google_data
                        ))
                
                return results
    
    except Exception as e:
        print(f"Search error: {e}")
        return []

async def get_latest_uploads() -> List[SearchResult]:
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get("https://tokybook.com/", timeout=10) as response:
                if response.status != 200:
                    return []
                
                html = await response.text()
                soup = BeautifulSoup(html, 'html.parser')
                
                results = []
                entries = soup.find_all("h2", {"class": "entry-title"})[:12]  # Latest 12
                
                for entry in entries:
                    link = entry.find("a")
                    if link:
                        title = link.get_text().strip()
                        url = link.get("href")
                        
                        # Enrich with Google Books data
                        google_data = await enrich_with_google_books(title)
                        
                        results.append(SearchResult(
                            title=title,
                            url=url,
                            **google_data
                        ))
                
                return results
    
    except Exception as e:
        print(f"Latest uploads error: {e}")
        return []

async def extract_mp3_links(book_url: str) -> List[str]:
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(book_url, timeout=10) as response:
                if response.status != 200:
                    print(f"Failed to fetch book page: {response.status}")
                    return []
                
                html = await response.text()
                soup = BeautifulSoup(html, 'html.parser')
                
                mp3_links = []
                scripts = soup.find_all("script")
                
                print(f"Extracting MP3 links from: {book_url}")
                print(f"Found {len(scripts)} script tags")
                
                for script in scripts:
                    if script.string and ".mp3" in script.string:
                        # Look for different patterns
                        patterns = [
                            r'"([^"]+\.mp3)"',  # Direct MP3 URLs in quotes
                            r'chapter_link_dropbox["\s]*:["\s]*"([^"]+)"',  # chapter_link_dropbox pattern
                            r'url["\s]*:["\s]*"([^"]+\.mp3)"',  # url: "something.mp3"
                            r'src["\s]*:["\s]*"([^"]+\.mp3)"',  # src: "something.mp3"
                        ]
                        
                        for pattern in patterns:
                            matches = re.findall(pattern, script.string)
                            for match in matches:
                                if match and '.mp3' in match:
                                    # Clean up the URL
                                    url = match.strip()
                                    
                                    # If it's a relative path, make it absolute
                                    if url.startswith('/'):
                                        url = f"https://files02.tokybook.com{url}"
                                    elif not url.startswith('http'):
                                        # Replace backslashes and spaces
                                        url_formatted = url.replace('\\', '/').replace(' ', '%20')
                                        url = f"https://files02.tokybook.com/audio/{url_formatted}"
                                    
                                    if url not in mp3_links:  # Avoid duplicates
                                        mp3_links.append(url)
                                        print(f"Found MP3 link: {url}")
                
                # Also check for audio tags
                audio_tags = soup.find_all("audio")
                for audio in audio_tags:
                    src = audio.get("src")
                    if src and '.mp3' in src:
                        if not src.startswith('http'):
                            src = urljoin(book_url, src)
                        if src not in mp3_links:
                            mp3_links.append(src)
                            print(f"Found audio tag MP3: {src}")
                
                # Check for source tags within audio
                source_tags = soup.find_all("source")
                for source in source_tags:
                    src = source.get("src")
                    if src and '.mp3' in src:
                        if not src.startswith('http'):
                            src = urljoin(book_url, src)
                        if src not in mp3_links:
                            mp3_links.append(src)
                            print(f"Found source tag MP3: {src}")
                
                print(f"Total MP3 links found: {len(mp3_links)}")
                return mp3_links
    
    except Exception as e:
        print(f"MP3 extraction error: {e}")
        import traceback
        traceback.print_exc()
        return []

# Download management
def sanitize_filename(filename: str) -> str:
    # Remove invalid characters for filenames
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    return filename.strip()

def create_download_path(author: str, series: str, title: str) -> Path:
    audiobooks_dir = Path(os.getenv('AUDIOBOOKS_DIR', './audiobooks'))
    
    # Sanitize components
    author = sanitize_filename(author) if author else "Unknown Author"
    title = sanitize_filename(title)
    
    if series:
        series = sanitize_filename(series)
        return audiobooks_dir / author / series / title
    else:
        return audiobooks_dir / author / title

async def download_chapter(session: aiohttp.ClientSession, url: str, filepath: Path, chapter_num: int) -> bool:
    try:
        filepath.parent.mkdir(parents=True, exist_ok=True)
        temp_filepath = filepath.with_suffix('.part')
        
        print(f"Downloading chapter {chapter_num} from: {url}")
        
        async with session.get(url, timeout=30) as response:
            print(f"Response status: {response.status}")
            
            if response.status == 200:
                content_length = response.headers.get('Content-Length')
                if content_length:
                    print(f"Chapter {chapter_num} size: {int(content_length) / 1024 / 1024:.2f} MB")
                
                async with aiofiles.open(temp_filepath, 'wb') as f:
                    downloaded = 0
                    async for chunk in response.content.iter_chunked(8192):
                        await f.write(chunk)
                        downloaded += len(chunk)
                
                # Verify file size
                if temp_filepath.stat().st_size == 0:
                    print(f"Chapter {chapter_num} downloaded but file is empty")
                    temp_filepath.unlink()
                    return False
                
                # Rename .part to .mp3
                temp_filepath.rename(filepath)
                print(f"Chapter {chapter_num} downloaded successfully")
                
                # Add ID3 tags
                try:
                    audio = MP3(filepath, ID3=ID3)
                    audio.tags.add(TIT2(encoding=3, text=f"Chapter {chapter_num}"))
                    audio.tags.add(TRCK(encoding=3, text=str(chapter_num)))
                    audio.save()
                except Exception as e:
                    print(f"ID3 tagging error: {e}")
                
                return True
            else:
                print(f"Failed to download chapter {chapter_num}: HTTP {response.status}")
                return False
                
    except asyncio.TimeoutError:
        print(f"Timeout downloading chapter {chapter_num}")
        return False
    except Exception as e:
        print(f"Error downloading chapter {chapter_num}: {e}")
        import traceback
        traceback.print_exc()
        return False

async def download_audiobook(queue_id: int):
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    
    try:
        # Get queue item
        cursor.execute("SELECT title, url, author, series FROM queue WHERE id = ?", (queue_id,))
        result = cursor.fetchone()
        if not result:
            return
        
        title, url, author, series = result
        
        # Update status to downloading
        cursor.execute("UPDATE queue SET status = 'downloading' WHERE id = ?", (queue_id,))
        conn.commit()
        await broadcast_queue_update()
        
        # Check if already exists
        download_path = create_download_path(author, series, title)
        if download_path.exists() and any(download_path.iterdir()):
            cursor.execute(
                "UPDATE queue SET status = 'completed', progress = 100, completed_at = ? WHERE id = ?",
                (datetime.now(), queue_id)
            )
            conn.commit()
            await broadcast_queue_update()
            return
        
        # Extract MP3 links
        mp3_links = await extract_mp3_links(url)
        if not mp3_links:
            raise Exception("No chapters found")
        
        # Download chapters
        download_path.mkdir(parents=True, exist_ok=True)
        
        async with aiohttp.ClientSession() as session:
            total_chapters = len(mp3_links)
            completed_chapters = 0
            
            for i, mp3_url in enumerate(mp3_links, 1):
                chapter_filename = f"{sanitize_filename(title)}_Chapter_{i:02d}.mp3"
                chapter_path = download_path / chapter_filename
                
                # Retry logic
                for attempt in range(3):
                    if await download_chapter(session, mp3_url, chapter_path, i):
                        completed_chapters += 1
                        progress = (completed_chapters / total_chapters) * 100
                        
                        cursor.execute("UPDATE queue SET progress = ? WHERE id = ?", (progress, queue_id))
                        conn.commit()
                        await broadcast_queue_update()
                        break
                    else:
                        if attempt == 2:  # Last attempt failed
                            raise Exception(f"Failed to download chapter {i}")
        
        # Mark as completed
        cursor.execute(
            "UPDATE queue SET status = 'completed', progress = 100, completed_at = ? WHERE id = ?",
            (datetime.now(), queue_id)
        )
        conn.commit()
        
        # Refresh Audiobookshelf library
        await refresh_audiobookshelf_library()
        
    except Exception as e:
        print(f"Download error: {e}")
        cursor.execute(
            "UPDATE queue SET status = 'failed', error_message = ? WHERE id = ?",
            (str(e), queue_id)
        )
        conn.commit()
    
    finally:
        conn.close()
        await broadcast_queue_update()

async def refresh_audiobookshelf_library():
    auto_refresh = get_setting('auto_refresh')
    if auto_refresh != 'true':
        return
    
    abs_url = get_setting('audiobookshelf_url')
    abs_token = get_setting('audiobookshelf_token')
    
    if not abs_url or not abs_token:
        return
    
    try:
        # Get libraries
        async with aiohttp.ClientSession() as session:
            headers = {'Authorization': f'Bearer {abs_token}'}
            async with session.get(f"{abs_url}/api/libraries", headers=headers) as response:
                if response.status == 200:
                    libraries = await response.json()
                    
                    # Refresh each library
                    for library in libraries.get('libraries', []):
                        library_id = library['id']
                        scan_url = f"{abs_url}/api/libraries/{library_id}/scan"
                        async with session.post(scan_url, headers=headers) as scan_response:
                            if scan_response.status == 200:
                                print(f"Refreshed library {library_id}")
    except Exception as e:
        print(f"Audiobookshelf refresh error: {e}")

# WebSocket for real-time updates
async def broadcast_queue_update():
    global websocket_connections
    
    if not websocket_connections:
        return
    
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, title, author, series, status, progress, created_at, completed_at, error_message
        FROM queue ORDER BY created_at DESC
    """)
    
    queue_items = []
    for row in cursor.fetchall():
        queue_items.append({
            'id': row[0],
            'title': row[1],
            'author': row[2],
            'series': row[3],
            'status': row[4],
            'progress': row[5],
            'created_at': row[6],
            'completed_at': row[7],
            'error_message': row[8]
        })
    
    conn.close()
    
    message = json.dumps({'type': 'queue_update', 'data': queue_items})
    
    # Remove disconnected websockets
    disconnected = set()
    for websocket in websocket_connections:
        try:
            await websocket.send_text(message)
        except:
            disconnected.add(websocket)
    
    websocket_connections -= disconnected

# Background task to process download queue
async def process_download_queue():
    while True:
        try:
            queue_id = await download_queue.get()
            await download_audiobook(queue_id)
            download_queue.task_done()
        except Exception as e:
            print(f"Queue processing error: {e}")

# API Routes
@app.on_event("startup")
async def startup_event():
    init_db()
    
    # Set initial password if provided
    initial_password = os.getenv('INITIAL_PASSWORD')
    if initial_password:
        conn = sqlite3.connect('app.db')
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]
        
        if user_count == 0:
            password_hash = hash_password(initial_password)
            cursor.execute("INSERT INTO users (password_hash) VALUES (?)", (password_hash,))
            conn.commit()
        
        conn.close()
    
    # Start download queue processor
    asyncio.create_task(process_download_queue())

@app.post("/api/login")
async def login(request: LoginRequest):
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users LIMIT 1")
    result = cursor.fetchone()
    conn.close()
    
    if not result:
        # No users exist, set password
        password_hash = hash_password(request.password)
        conn = sqlite3.connect('app.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (password_hash) VALUES (?)", (password_hash,))
        conn.commit()
        conn.close()
        
        return {"token": password_hash, "message": "Password set successfully"}
    
    if verify_password(request.password, result[0]):
        return {"token": result[0]}
    else:
        raise HTTPException(status_code=401, detail="Invalid password")

@app.post("/api/change-password")
async def change_password(request: PasswordChangeRequest, user_id: int = Depends(get_current_user)):
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,))
    result = cursor.fetchone()
    
    if not result or not verify_password(request.old_password, result[0]):
        conn.close()
        raise HTTPException(status_code=400, detail="Invalid old password")
    
    new_password_hash = hash_password(request.new_password)
    cursor.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_password_hash, user_id))
    conn.commit()
    conn.close()
    
    return {"message": "Password changed successfully", "token": new_password_hash}

@app.get("/api/search")
async def search(q: str, user_id: int = Depends(get_current_user)):
    results = await search_tokybook(q)
    return {"results": results}

@app.get("/api/latest")
async def latest(user_id: int = Depends(get_current_user)):
    results = await get_latest_uploads()
    return {"results": results}

@app.post("/api/download")
async def add_to_queue(request: DownloadRequest, user_id: int = Depends(get_current_user)):
    # Check if already exists
    download_path = create_download_path(request.author, request.series, request.title)
    if download_path.exists() and any(download_path.iterdir()):
        raise HTTPException(status_code=400, detail="Audiobook already downloaded")
    
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO queue (title, url, author, series)
        VALUES (?, ?, ?, ?)
    """, (request.title, request.url, request.author, request.series))
    
    queue_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    # Add to download queue
    await download_queue.put(queue_id)
    await broadcast_queue_update()
    
    return {"message": "Added to download queue", "queue_id": queue_id}

@app.get("/api/queue")
async def get_queue(user_id: int = Depends(get_current_user)):
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, title, author, series, status, progress, created_at, completed_at, error_message
        FROM queue ORDER BY created_at DESC
    """)
    
    queue_items = []
    for row in cursor.fetchall():
        queue_items.append(QueueItem(
            id=row[0],
            title=row[1],
            author=row[2],
            series=row[3],
            status=row[4],
            progress=row[5],
            created_at=row[6],
            completed_at=row[7],
            error_message=row[8]
        ))
    
    conn.close()
    return {"queue": queue_items}

@app.delete("/api/queue/{queue_id}")
async def cancel_download(queue_id: int, user_id: int = Depends(get_current_user)):
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM queue WHERE id = ? AND status IN ('waiting', 'failed')", (queue_id,))
    conn.commit()
    conn.close()
    
    await broadcast_queue_update()
    return {"message": "Download cancelled"}

@app.get("/api/settings")
async def get_settings(user_id: int = Depends(get_current_user)):
    return {
        "google_books_api_key": get_setting('google_books_api_key') or '',
        "audiobookshelf_url": get_setting('audiobookshelf_url') or '',
        "audiobookshelf_token": get_setting('audiobookshelf_token') or '',
        "auto_refresh": get_setting('auto_refresh') != 'false'
    }

@app.post("/api/settings")
async def update_settings(settings: Settings, user_id: int = Depends(get_current_user)):
    if settings.google_books_api_key is not None:
        set_setting('google_books_api_key', settings.google_books_api_key)
    if settings.audiobookshelf_url is not None:
        set_setting('audiobookshelf_url', settings.audiobookshelf_url.rstrip('/'))
    if settings.audiobookshelf_token is not None:
        set_setting('audiobookshelf_token', settings.audiobookshelf_token)
    
    set_setting('auto_refresh', 'true' if settings.auto_refresh else 'false')
    
    return {"message": "Settings updated successfully"}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    global websocket_connections
    
    await websocket.accept()
    websocket_connections.add(websocket)
    
    try:
        # Send initial queue state
        await broadcast_queue_update()
        
        # Keep connection alive
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        websocket_connections.remove(websocket)

# Serve React frontend
app.mount("/", StaticFiles(directory="frontend/build", html=True), name="frontend")

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv('APP_PORT', 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)