import contextlib
import json
import pathlib
import time

def lock(name):
    lockfile = pathlib.Path(f'{name}.lock')
    for i in range(5):
        try:
            lockfile.symlink_to('/dev/null')
            return
        except FileExistsError:
            time.sleep(1)
    raise TimeoutError(f'could not lock {name}')

def unlock(name):
    lockfile = pathlib.Path(f'{name}.lock')
    lockfile.unlink(missing_ok=True)

@contextlib.contextmanager
def locked(name):
    lock(name)
    try:
        yield name
    finally:
        unlock(name)

def read(name):
    with open(f'{name}.json', 'a+', encoding='utf-8') as f:
        f.seek(0)
        return json.loads(f.read() or '{}')

def write(name, data):
    with open(f'{name}.json', 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)
        f.close()

def load(name):
    with locked(name):
        return read(name)

def save(name, data):
    with locked(name):
        write(name, data)
