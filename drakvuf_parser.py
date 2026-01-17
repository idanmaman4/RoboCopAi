cat robocop/python_parsers/sql_parser.py 
#!/usr/bin/env python3
import sys
import ctypes
import threading
import queue
import signal
from pony.orm import *
from raw_objects.syscall import SyscallTraceResults
from sql.sql_login import *
import pprint


CHUNK_SIZE = 1024 * 1024 * 10   # 10MB
QUEUE_MAXSIZE = 1_000_000
DB_COMMIT_EVERY = 10_000
QUEUE_PUT_TIMEOUT = 0.1

INVALID_HANDLE_VAL = 1337

shutdown_event = threading.Event()



def handle_signal(signum, frame):
    shutdown_event.set()

signal.signal(signal.SIGINT, handle_signal)
signal.signal(signal.SIGTERM, handle_signal)



if len(sys.argv) != 2:
    print("Usage: ingest_syscalls.py <TEST_NAME>", file=sys.stderr)
    sys.exit(1)

TEST_NAME = sys.argv[1]


syscall_queue = queue.Queue(maxsize=QUEUE_MAXSIZE)



def flush_buffer(records, test):
    pprint.pprint(records[0])
    for r in records:
        Syscall(
            syscall_num=r["syscall_num"],
            handle_operation=r["handle_operation"] if r["ret_handle"] != INVALID_HANDLE_VAL else None,
            syscall_mode=r["syscall_mode"],
            handle_1_val=r["handle_1_val"] if r["handle_1_val"] != INVALID_HANDLE_VAL else None,
            handle_2_val=r["handle_2_val"] if r["handle_2_val"] != INVALID_HANDLE_VAL else None,
            ret_handle=r["ret_handle"] if r["ret_handle"] != INVALID_HANDLE_VAL else None,
            closed_handle=r["closed_handle"] if r["closed_handle"] != INVALID_HANDLE_VAL else None,
            handle_1_access=r["handle_1_access"] if r["handle_1_val"] != INVALID_HANDLE_VAL else None,
            handle_2_access=r["handle_2_access"] if r["handle_2_val"] != INVALID_HANDLE_VAL else None,
            handle_1_access_mode=r["handle_1_access_mode"] if r["handle_1_val"] != INVALID_HANDLE_VAL else None,
            handle_2_access_mode=r["handle_2_access_mode"] if r["handle_2_val"] != INVALID_HANDLE_VAL else None,
            pid=r["pid"],
            tid=r["tid"],
            ts=r["current_time"],
            process_name=r["process_name"],
            test=test
        )


@db_session()
def db_writer():
    try:
        buffer = []
        total = 0

        test = Test.get(name=TEST_NAME)
        if test is None:
            test = Test(name=TEST_NAME)
            commit()  # 🔥 ENSURE TEST EXISTS IN DB

        while True:
            item = syscall_queue.get()

            if item is None:
                break

            buffer.append(item)

            if len(buffer) >= DB_COMMIT_EVERY:
                try:
                    flush_buffer(buffer, test)
                    commit()                # 🔥 REAL COMMIT
                    total += len(buffer)
                    buffer.clear()
                except:
                    buffer.clear()
        if buffer:
            try:
                flush_buffer(buffer, test)
                commit()
                total += len(buffer)
            except:
                ...
        print(f"[DB] committed {total} syscalls", file=sys.stderr)
    except:
        ...
writer_thread = threading.Thread(target=db_writer)
writer_thread.start()



def read_stdin():
    struct_size = ctypes.sizeof(SyscallTraceResults)
    buf = b""
    count = 0

    print(f"Struct size = {struct_size}", file=sys.stderr)

    while not shutdown_event.is_set():
        chunk = sys.stdin.buffer.read(CHUNK_SIZE)
        if not chunk:
            break

        buf += chunk

        while len(buf) >= struct_size:
            raw = buf[:struct_size]
            buf = buf[struct_size:]

            try:
                obj = SyscallTraceResults.from_buffer_copy(raw)
                syscall_queue.put(obj.to_dict(), timeout=QUEUE_PUT_TIMEOUT)
            except Exception as e:
                print(f"Parse error: {e}", file=sys.stderr)

            count += 1
            if count % 10_000 == 0:
                print(f"Read {count}", file=sys.stderr)

    print(f"Reader done: {count}", file=sys.stderr)

try:
    read_stdin()
finally:
    shutdown_event.set()
    syscall_queue.put(None)
    writer_thread.join()
    print("Shutdown complete", file=sys.stderr)