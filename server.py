import socket
from dns_methods import unpack_dns_recv, build_dns_response

from constants import SERVER_IP, PORT, NOERROR_CODE
from dns_resolver import resolve


def handle_request(data: bytes) -> bytes | None:
    try:
        request = unpack_dns_recv(data)
        query_id = request["header"]["id"]
        rd = request["header"]["rd"]
        question = request["questions"][0]
    except Exception:
        return None

    try:
        result = resolve(question["name"], question["type"])
    except Exception:
        result = None

    if result is None:
        result = {"rcode": NOERROR_CODE, "records": []}

    try:
        return build_dns_response(
            query_id, rd, question, result["rcode"], result["records"]
        )
    except Exception:
        return build_dns_response(query_id, rd, question, NOERROR_CODE, [])


def run_server():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_socket:
        server_socket.bind((SERVER_IP, PORT))

        while True:
            try:
                data, client_address = server_socket.recvfrom(4096)
                response = handle_request(data)
                if response is not None:
                    server_socket.sendto(response, client_address)
            except OSError:
                continue