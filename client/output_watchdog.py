import time
from pathlib import Path
import shutil
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer
from artifact_uploader import ArtifactUploader  # Dateiname der Klasse anpassen

WATCHFOLDER = './watchfolder'
SECURE_AREA = './secure_area'
KEY_PATH = 'keys/client_1.pem'
BASE_URL = 'http://localhost:8000'

uploader = ArtifactUploader(
    key_path = KEY_PATH,
    base_url = BASE_URL,
)

class MyEventHandler(FileSystemEventHandler):
    def on_any_event(self, event: FileSystemEvent) -> None:
        print(event)
        match event.event_type:
            case 'created':
                return self.handel_file_creation(event)
            case 'modified':
                return self.handel_file_modification(event)
            case 'deleted':
                return self.handel_file_deletion(event)

    def handel_file_creation(self, event: FileSystemEvent) -> None:
        print("handel_file_creation")
        self.upload_signature(event)
        print(event)

    def handel_file_modification(self, event: FileSystemEvent) -> None:
        print("handel_file_modification")
        print(event)

    def handel_file_deletion(self, event: FileSystemEvent) -> None:
        print("handel_file_deletion")
        print(event)

    def upload_signature(sefl,event):
        file_path = event.src_path
        try:
            uploader.upload(file_path)
        except:
            print("UPLOAD FAILED")
            return
        
        src = Path(file_path)
        parts = list(src.parts)  
        watchfolfer_path = Path(WATCHFOLDER)                        # Pfadkomponenten extrahieren
        parts[parts.index(str(watchfolfer_path))] = SECURE_AREA                  # äußeren Ordner ersetzen
        dst = Path(*parts)                                       # Zielpfad rekonstruieren
        dst.parent.mkdir(parents=True, exist_ok=True)            # Zielverzeichnis anlegen
        shutil.move(src, dst)

event_handler = MyEventHandler()
observer = Observer()
observer.schedule(event_handler, WATCHFOLDER, recursive=True)
observer.start()

try:
    while True:
        time.sleep(1)
finally:
    observer.stop()
    observer.join()