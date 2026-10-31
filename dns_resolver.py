import socket
import struct

from constants import (
    ROOT_IP, PORT, TIMELIMIT, ID, A_CODE, CNAME_CODE, NS_CODE,
    DEPTH_LIMIT, NOERROR_CODE, NXDOMAIN_CODE,
)
from dns_methods import build_dns_req, unpack_dns_recv


def query_server(domain, ip_address, qtype=A_CODE):
    request = build_dns_req(domain, qtype)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(TIMELIMIT)
            s.sendto(request, (ip_address, PORT))
            data, _ = s.recvfrom(4096)
        response = unpack_dns_recv(data)
    except (OSError, IndexError, struct.error, UnicodeDecodeError, ValueError):
        return None

    if response["header"]["id"] != ID:
        return None

    return response


def make_result(rcode, records):
    return {"rcode": rcode, "records": records}


def find_records(records, record_type):
    return [record for record in records if record["type"] == record_type]


def get_glue(response):
    return {
        record["name"].lower(): record["rdata"]
        for record in find_records(response["additionals"], A_CODE)
    }


def get_ns_names(response):
    return [record["rdata"] for record in find_records(response["authorities"], NS_CODE)]


def resolve_ns_ip(name, depth):
    result = resolve(name, A_CODE, ROOT_IP, depth + 1)
    if result is None:
        return None
    a_records = find_records(result["records"], A_CODE)
    return a_records[0]["rdata"] if a_records else None


def iter_next_servers(response, depth):
    """Отдаёт IP следующих серверов по одному: сначала известные, потом те, чей IP надо искать."""
    glue = get_glue(response)
    ns_names = get_ns_names(response)

    for name in ns_names:
        if name.lower() in glue:
            yield glue[name.lower()]

    for name in ns_names:
        if name.lower() not in glue:
            server_ip = resolve_ns_ip(name, depth)
            if server_ip is not None:
                yield server_ip


def ask_next_servers(domain, qtype, response, depth):
    for server_ip in iter_next_servers(response, depth):
        result = resolve(domain, qtype, server_ip, depth + 1)
        if result is not None:
            return result
    return None


def resolve_cname(cnames, qtype, depth):
    target = resolve(cnames[0]["rdata"], qtype, ROOT_IP, depth + 1)
    if target is None:
        return None
    return make_result(target["rcode"], cnames + target["records"])


def resolve(domain, qtype=A_CODE, ip_address=ROOT_IP, depth=0):
    if depth > DEPTH_LIMIT:
        return None

    response = query_server(domain, ip_address, qtype)
    if response is None:
        return None

    rcode = response["header"]["rcode"]
    if rcode == NXDOMAIN_CODE:
        return make_result(NXDOMAIN_CODE, [])
    if rcode != NOERROR_CODE:
        return None

    answers = response["answers"]
    if find_records(answers, qtype):
        return make_result(NOERROR_CODE, answers)

    cnames = find_records(answers, CNAME_CODE)
    if cnames:
        return resolve_cname(cnames, qtype, depth)

    if not get_ns_names(response):
        return make_result(NOERROR_CODE, [])

    return ask_next_servers(domain, qtype, response, depth)