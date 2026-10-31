import socket
import struct

from constants import (
    ROOT_IP,
    ID,
    FLAGS,
    QDCOUNT,
    ANCOUNT,
    NSCOUNT,
    ARCOUNT,
    QTYPE,
    QCLASS,
    A_CODE,
    NS_CODE,
    CNAME_CODE,
)

address = "google.com"


def build_dns_req(address: str, qtype: int = QTYPE) -> bytes:
    header = struct.pack("!6H", ID, FLAGS, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT)
    qname = b""

    for label in address.rstrip(".").split("."):
        qname += bytes([len(label)]) + label.encode()

    qname += b"\x00"
    question = qname + struct.pack(">HH", qtype, QCLASS)
    return header + question


def read_name(data, offset):
    length = data[offset]

    if length == 0:
        return "", offset + 1

    if length & 0xC0 == 0xC0:
        pointer = ((length & 0x3F) << 8) | data[offset + 1]
        name, _ = read_name(data, pointer)
        return name, offset + 2

    label = data[offset + 1 : offset + 1 + length].decode()
    rest, end = read_name(data, offset + 1 + length)
    return (label + "." + rest if rest else label), end


def read_record(data, offset):
    name, offset = read_name(data, offset)
    rtype, rclass, ttl, rdlength = struct.unpack_from("!HHIH", data, offset)
    offset += 10

    if rtype == A_CODE:
        rdata = socket.inet_ntop(socket.AF_INET, data[offset : offset + 4])
    elif rtype in (NS_CODE, CNAME_CODE):
        rdata, _ = read_name(data, offset)
    else:
        rdata = data[offset : offset + rdlength]

    record = {"name": name, "type": rtype, "class": rclass, "ttl": ttl, "rdata": rdata}
    return record, offset + rdlength


def unpack_dns_recv(data: bytes):
    id_, flags, qdcount, ancount, nscount, arcount = struct.unpack("!6H", data[:12])

    rcode = flags & 0xF
    aa = flags & (1 << 10)
    offset = 12

    header = {
        "id": id_,
        "rcode": rcode,
        "aa": aa,
        "qdcount": qdcount,
        "ancount": ancount,
        "nscount": nscount,
        "arcount": arcount,
    }

    questions = []
    for _ in range(qdcount):
        name, offset = read_name(data, offset)
        qtype, qclass = struct.unpack_from("!HH", data, offset)
        offset += 4
        questions.append({"name": name, "type": qtype, "class": qclass})

    sections = []
    for count in (ancount, nscount, arcount):
        records = []
        for _ in range(count):
            record, offset = read_record(data, offset)
            records.append(record)
        sections.append(records)
    answers, authorities, additionals = sections

    return {
        "header": header,
        "questions": questions,
        "answers": answers,
        "authorities": authorities,
        "additionals": additionals,
    }


request: bytes = build_dns_req(address)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
s.sendto(request, (ROOT_IP, 53))
data, _ = s.recvfrom(4096)
print(unpack_dns_recv(data)["authorities"])
