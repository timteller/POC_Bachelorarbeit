import time
from pathlib import Path
import shutil
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer
from artifact_checker import ArtifactChecker  # Dateiname der Klasse anpassen

SECURE_AREA = './secure_area'
QUARANTINE_AREA = './quarantine_area'
BASE_URL = 'http://localhost:8000'

checker = ArtifactChecker(
    base_url = BASE_URL,
)

class MyEventHandler(FileSystemEventHandler):
    def on_any_event(self, event: FileSystemEvent) -> None:
        # print(event)
        match event.event_type:
            case 'created':
                return self.handel_file_creation(event)
            case 'modified':
                return self.handel_file_modification(event)
            case 'deleted':
                return self.handel_file_deletion(event)

    def handel_file_creation(self, event: FileSystemEvent) -> None:
        print("handel_file_creation")
        self.check_file(event)
        # print(event)

    def handel_file_modification(self, event: FileSystemEvent) -> None:
        print("handel_file_modification")
        self.check_file(event)
        # print(event)

    def handel_file_deletion(self, event: FileSystemEvent) -> None:
        print("handel_file_deletion")
        # print(event)

    def check_file(sefl,event):
        file_path = event.src_path
        result = checker.check(file_path)
        if result is None:
            return
        if result == False:
            src = Path(file_path)
            parts = list(src.parts)  
            secure_area_path = Path(SECURE_AREA)                        # Pfadkomponenten extrahieren
            parts[parts.index(str(secure_area_path))] = QUARANTINE_AREA                  # äußeren Ordner ersetzen
            dst = Path(*parts)                                       # Zielpfad rekonstruieren
            dst.parent.mkdir(parents=True, exist_ok=True)            # Zielverzeichnis anlegen
            shutil.move(src, dst)
        

event_handler = MyEventHandler()
observer = Observer()
observer.schedule(event_handler, SECURE_AREA, recursive=True)
observer.start()

try:
    while True:
        time.sleep(1)
finally:
    observer.stop()
    observer.join()