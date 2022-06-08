import os
import subprocess
import time
import socket
import signal
import psutil
from prettytable import PrettyTable

EXECUTABLE = "./proxyServer"
PORT = 7700


def recv_from_socket(s: socket.socket) -> bytes:
    f = b''
    while True:
        data = s.recv(1024)
        if not data:
            break
        f = f + data
    return f


def connect_and_send(s: socket.socket, request: bytes, timeout=60) -> None:
    s.connect(('localhost', PORT))
    s.settimeout(timeout)
    s.sendall(request)
    return


def valgrind_test():
    print("[+] running valgrind with full check and debug mode")
    valgrind = subprocess.Popen(
        "valgrind --leak-check=full --tool=memcheck --show-leak-kinds=all --track-origins=yes --verbose "
        f"--error-exitcode=1 -v --log-file=valgrind-out.txt {EXECUTABLE} {PORT} 2 2 expected/filter.txt",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=True)

    time.sleep(5)
    request = b'GET / HTTP/1.1\r\nHost: testingmcafeesites.com\r\n\r\n'

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            connect_and_send(s, request)
            res1 = recv_from_socket(s)

        except (socket.timeout, ConnectionRefusedError) as e:
            if isinstance(e, ConnectionRefusedError):
                outs, errs = valgrind.communicate(timeout=10)
                if 'Address already in use' in str(errs):
                    raise ConnectionResetError(e)
                print("[-] proxyServer crashed...")
                print("[-] Valgrind Test failed...")
            print(e)
            if psutil.pid_exists(valgrind.pid):
                os.kill(valgrind.pid, signal.SIGKILL)
            return False

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            connect_and_send(s, request)
            res2 = recv_from_socket(s)

        except (socket.timeout, ConnectionRefusedError, ConnectionResetError) as e:
            print(e)
            if psutil.pid_exists(valgrind.pid):
                os.kill(valgrind.pid, signal.SIGKILL)
            return False

    try:
        stdout, stderr = valgrind.communicate(timeout=60)

    except subprocess.TimeoutExpired as e:
        print(e)
        if psutil.pid_exists(valgrind.pid):
            os.kill(valgrind.pid, signal.SIGKILL)
        return False

    if valgrind.returncode != 0:
        if psutil.pid_exists(valgrind.pid):
            os.kill(valgrind.pid, signal.SIGKILL)
        print("[-] Found errors... Valgrind test failed.")
        return False

    return True


def deadlock():
    print("[+] Test Deadlock")
    proc = subprocess.Popen(
        [EXECUTABLE, str(PORT), "4", "8", 'expected/filter.txt'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    time.sleep(3)
    request1 = b"GET / HTTP/1.1\r\nHost: httpbin.org\r\n\r\n"
    request2 = b"GET / HTTP/1.1\r\nHost: neverssl.com\r\n\r\n"

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s1, \
            socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s2, \
            socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s3, \
            socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s4, \
            socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s5, \
            socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s6, \
            socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s7, \
            socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s8:

        try:
            connect_and_send(s1, request1, timeout=120)

        except (socket.timeout, ConnectionRefusedError) as e:
            if isinstance(e, ConnectionRefusedError):
                outs, errs = proc.communicate(timeout=10)
                if 'Address already in use' in str(errs):
                    raise ConnectionResetError(e)
                print("[-] proxyServer crashed...")
            if psutil.pid_exists(proc.pid):
                os.kill(proc.pid, signal.SIGKILL)
            print(e)
            return False

        try:
            connect_and_send(s2, request1, timeout=120)
            connect_and_send(s3, request2)
            connect_and_send(s4, request2)
            connect_and_send(s5, request1)
            connect_and_send(s6, request1)
            connect_and_send(s7, request2)
            connect_and_send(s8, request2)

            recv_from_socket(s1)
            recv_from_socket(s2)
            recv_from_socket(s3)
            recv_from_socket(s4)
            recv_from_socket(s5)
            recv_from_socket(s6)
            recv_from_socket(s7)
            recv_from_socket(s8)

        except (socket.timeout, ConnectionRefusedError, ConnectionResetError) as e:
            if psutil.pid_exists(proc.pid):
                os.kill(proc.pid, signal.SIGKILL)
            print(e)
            return False

    try:
        stdout, stderr = proc.communicate(timeout=30)
        if proc.returncode == 0 and stderr == b'':
            return True

        elif proc.returncode == 139:
            print("You had a segfault.")
            return False

        elif proc.returncode == 131 or proc.returncode == 132 or proc.returncode == 134 or proc.returncode == 136:
            print("You had core dump")
            return False

        else:
            print("[-] Test Deadlock failed.")
            return False

    except subprocess.TimeoutExpired as e:
        print(e)
        return False


def response_from_filesystem():
    print("[+] Test Response From Server")
    proc = subprocess.Popen(
        [EXECUTABLE, str(PORT), "1", "1", 'expected/filter.txt'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    time.sleep(3)
    request = b"GET /images2015/wa_banner_excellence1024-plain.jpg HTTP/1.1\r\nHost: webaward.org\r\n\r\n"

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            connect_and_send(s, request)

        except (socket.timeout, ConnectionRefusedError) as e:
            if isinstance(e, ConnectionRefusedError):
                outs, errs = proc.communicate(timeout=10)
                if 'Address already in use' in str(errs):
                    raise ConnectionResetError(e)
                print("[-] proxyServer crashed...")
            if psutil.pid_exists(proc.pid):
                os.kill(proc.pid, signal.SIGKILL)
            print(e)
            return False

        try:
            res = recv_from_socket(s)

        except (socket.timeout, ConnectionResetError) as e:
            print(e)
            return False

    try:
        headers_idx = res.index(b'\r\n\r\n') + 4
        headers = res[:headers_idx - 1]
        content = res[headers_idx:]

        with open('stdout_check_headers.txt', 'wb') as out_file:
            out_file.write(headers)

    except ValueError as e:
        print(r"[-] The end of the headers: '\r\n\r\n' not found...")
        print("[-] Test Response From Server failed. Please check stdout_check_headers.txt")
        return False

    try:
        size = os.stat('webaward.org/images2015/wa_banner_excellence1024-plain.jpg').st_size

    except FileNotFoundError as e:
        print("[-] Cannot find the requested image...")
        print("[-] Test Response From Server failed.")
        return False

    headers = headers.lower()
    OK200 = b'http/1.0 200 ok\r\n'
    OK200_v2 = b'http/1.1 200 ok\r\n'
    content_length = b'content-length: %d\r\n' % size
    content_type = b'content-type: image/jpeg\r\n'
    c_close = b'connection: close\r\n'
    passed = True

    if OK200 not in headers and OK200_v2 not in headers:
        print("[-] 200 OK response is invalid/missing")
        passed = False

    if content_length not in headers:
        print("[-] Content-Length header is invalid/missing")
        passed = False

    if content_type not in headers:
        print("[-] Content-Type header is invalid/missing")
        passed = False

    if c_close not in headers:
        print("[-] Connection: close header is invalid/missing")
        passed = False

    if size != len(content):
        print("[-] Raw data from socket != Raw data from filesystem")
        print(f"[-] Size of raw bayes from socket: {len(content)} !="
              f"Size of raw bytes from file: {size}")
        passed = False

    if psutil.pid_exists(proc.pid):
        os.kill(proc.pid, signal.SIGKILL)

    if not passed:
        print("[-] Test Response From Server failed.")

    return passed


def content_reliability():
    print("[+] Test Content Reliability")
    proc = subprocess.Popen(
        [EXECUTABLE, str(PORT), "1", "1", 'expected/filter.txt'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    time.sleep(3)
    request = b"GET /images2015/wa_banner_excellence1024-plain.jpg HTTP/1.1\r\nHost: webaward.org\r\n\r\n"

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            connect_and_send(s, request, timeout=120)

        except (socket.timeout, ConnectionRefusedError) as e:
            if isinstance(e, ConnectionRefusedError):
                outs, errs = proc.communicate(timeout=10)
                if 'Address already in use' in str(errs):
                    print(errs)
                    raise ConnectionResetError(e)
                print("[-] proxyServer crashed...")
            if psutil.pid_exists(proc.pid):
                os.kill(proc.pid, signal.SIGKILL)
            print(e)
            return False

        try:
            recv_from_socket(s)

        except (socket.timeout, ConnectionResetError) as e:
            print(e)
            return False

    if psutil.pid_exists(proc.pid):
        os.kill(proc.pid, signal.SIGKILL)

    try:
        with open('webaward.org/images2015/wa_banner_excellence1024-plain.jpg', 'rb') as out_file, \
                open('expected/image.jpg', 'rb') as expected:
            res = out_file.readlines()
            exp = expected.readlines()

            if res != exp:
                print("[-] Test Content Correctness failed."
                      "Please check webaward.org/images2015/wa_banner_excellence1024-plain.jpg")
                return False

    except FileNotFoundError as e:
        print(e)
        return False

    return True


def response_from_socket():
    print("[+] Test Response From Socket")
    proc = subprocess.Popen(
        [EXECUTABLE, str(PORT), "1", "1", 'expected/filter.txt'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    time.sleep(3)
    request = b"GET /index.html HTTP/1.1\r\nHost: octopress.org\r\n\r\n"

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            connect_and_send(s, request)

        except (socket.timeout, ConnectionRefusedError) as e:
            if isinstance(e, ConnectionRefusedError):
                outs, errs = proc.communicate(timeout=10)
                if 'Address already in use' in str(errs):
                    raise ConnectionResetError(e)
                print("[-] proxyServer crashed...")
            if psutil.pid_exists(proc.pid):
                os.kill(proc.pid, signal.SIGKILL)
            print(e)
            return False

        try:
            with open('stdout_res_from_socket.txt', 'wb') as out_file:
                out_file.write(recv_from_socket(s))

        except (socket.timeout, ConnectionResetError) as e:
            print(e)
            return False

    if psutil.pid_exists(proc.pid):
        os.kill(proc.pid, signal.SIGKILL)

    with open('stdout_res_from_socket.txt', 'rb') as out_file, open('expected/octopress.html', 'rb') as expected:
        res = out_file.readlines()
        try:
            page_idx = res.index(b'<!DOCTYPE html>\n')

        except ValueError as e:
            print("[-] <!DOCTYPE html> not found... Some Content is missing...")
            print("[-] Test Response From Socket failed. Check stdout_res_from_socket.txt")
            return False

        res = res[page_idx:]
        exp = expected.readlines()

        if res != exp:
            print("[-] Some Content is missing...")
            print("[-] Test Response From Socket failed. Please check stdout_res_from_socket.txt")
            return False
    return True


def client_server_errors(out_file_name, expected_file, request):
    err_type = expected_file.split(os.sep)[1].split('.')[0]
    print(f"[+] Test {err_type}")
    proc = subprocess.Popen(
        [EXECUTABLE, str(PORT), "1", "1", 'expected/filter.txt'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    time.sleep(3)

    with open(out_file_name, 'wb') as out_file:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                connect_and_send(s, request)

            except (socket.timeout, ConnectionRefusedError) as e:
                if isinstance(e, ConnectionRefusedError):
                    outs, errs = proc.communicate(timeout=10)
                    if 'Address already in use' in str(errs):
                        raise ConnectionResetError(e)
                    print("[-] proxyServer crashed...")
                if psutil.pid_exists(proc.pid):
                    os.kill(proc.pid, signal.SIGKILL)
                print(e)
                return False

            try:
                out_file.write(recv_from_socket(s))

            except (socket.timeout, ConnectionResetError) as e:
                print(e)
                return False

    try:
        out, err = proc.communicate(timeout=30)

    except subprocess.TimeoutExpired as e:
        print(e)
        return False

    if psutil.pid_exists(proc.pid):
        os.kill(proc.pid, signal.SIGKILL)

    try:
        with open(out_file_name, 'r') as out_file, open(expected_file, 'r') as expected:
            res = out_file.read().strip()
            exp = expected.read().strip()
            if res != exp:
                print(f"[-] Test {err_type} failed. Please check out_{err_type.lower()}.txt")
                return False

    except UnicodeError as e:
        print(e)
        return False

    return True


def test_usage():
    print("[+] Test usage")
    try:
        with open("stdout_test_usage.txt", 'w') as out_file:
            subprocess.run(
                f'{EXECUTABLE}',
                stdout=out_file,
                text=True,
                shell=True,
                timeout=20,
            )

    except subprocess.TimeoutExpired as e:
        print(e)
        return False

    with open('stdout_test_usage.txt') as out_file:
        r = out_file.read().rstrip()

    with open('expected/usage.txt') as expected_file:
        e = expected_file.read().rstrip()

    if r != e:
        print("[-] Test with no args failed. Please check stdout_test_usage.txt")
        return False

    return True


def setup():
    if os.path.isfile(EXECUTABLE):
        os.remove(EXECUTABLE)

    with open("stdout_compilation.txt", 'w') as out_file:
        c = subprocess.run(
            f'gcc -Wall {EXECUTABLE}.c threadpool.c threadpool.h -o proxyServer -lpthread',
            stderr=out_file,
            stdout=out_file,
            shell=True,
        )

    with open("stdout_compilation.txt") as out_file:
        res = out_file.read()
        return_val = None
        if bytes(res, 'utf-8') == b'':
            print("Ex. compiled successfully.")
            return_val = "Compiled"

        if "warning: " in res:
            print("Warnings during compilation")
            return_val = "Warnings"

        if "error: " in res:
            print("\nSomething didn't go right when compiling your C source "
                  "please check stdout_compilation.txt\n")
            return_val = "Error"
        return return_val


if __name__ == '__main__':
    setup()
    test_valgrind = valgrind_test()
    PORT = PORT + 1
    t_usage = test_usage()
    stdout_bad_request = 'out_bad_request.txt'
    bad_request = b"GET /index.html HTTP/1.1\r\n\r\n"
    stdout_not_implemented = 'out_not-implemented.txt'
    not_implemented = b"DELETE /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    stdout_not_found = 'out_not_found.txt'
    not_found = b"GET /index.html HTTP/1.1\r\nHost: example.corn\r\n\r\n"
    stdout_forbidden_v1 = 'out_forbidden_v1.txt'
    forbidden_v1 = b"GET /index.html HTTP/1.1\r\nHost: info.cern.ch\r\n\r\n"
    stdout_forbidden_v2 = 'out_forbidden_v2.txt'
    forbidden_v2 = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    test_bad_request = client_server_errors(stdout_bad_request, 'expected/Bad Request.txt', bad_request)
    PORT = PORT + 1
    test_not_implemented = client_server_errors(stdout_not_implemented, 'expected/Not Implemented.txt', not_implemented)
    PORT = PORT + 1
    test_not_found = client_server_errors(stdout_not_found, 'expected/Not Found.txt', not_found)
    PORT = PORT + 1
    test_forbidden_v1 = client_server_errors(stdout_forbidden_v1, 'expected/Forbidden.txt', forbidden_v1)
    PORT = PORT + 1
    test_forbidden_v2 = client_server_errors(stdout_forbidden_v2, 'expected/Forbidden.txt', forbidden_v2)
    PORT = PORT + 1
    test_response_from_socket = response_from_socket()
    PORT = PORT + 1
    test_content_reliability = content_reliability()
    PORT = PORT + 1
    test_response_from_filesystem = response_from_filesystem()
    PORT = PORT + 1
    test_deadlock = deadlock()

    t = PrettyTable(['Test', 'Result'])
    t.align['Test'] = 'l'
    t.add_row(['Valgrind', test_valgrind])
    t.add_row(['Usage', t_usage])
    t.add_row(['Bad Request', test_bad_request])
    t.add_row(['Not Implemented', test_not_implemented])
    t.add_row(['Not Found', test_not_found])
    t.add_row(['Forbidden 1', test_forbidden_v1])
    t.add_row(['Forbidden 2', test_forbidden_v2])
    t.add_row(['Response From Socket', test_response_from_socket])
    t.add_row(['Content Reliability', test_content_reliability])
    t.add_row(['Response From Filesystem', test_response_from_filesystem])
    t.add_row(['Deadlock', test_deadlock])
    print(t)
