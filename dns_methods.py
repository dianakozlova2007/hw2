import struct
import socket

from constants import (
    A_CODE,
    NS_CODE,
    CNAME_CODE,
    QTYPE,
    ID,
    FLAGS,
    QDCOUNT,
    ANCOUNT,
    NSCOUNT,
    ARCOUNT,
    QCLASS,
)


def pack_name(domain: str) -> bytes:
    qname = b""
    for label in domain.rstrip(".").split("."):
        if label:
            qname += bytes([len(label)]) + label.encode()

    return qname + b"\x00"


def pack_record(record: dict) -> bytes | None:
    rtype = record["type"]

    if rtype == A_CODE:
        rdata = socket.inet_aton(record["rdata"])
    elif rtype in (NS_CODE, CNAME_CODE):
        rdata = pack_name(record["rdata"])
    else:
        return None

    return (
        pack_name(record["name"])
        + struct.pack("!HHIH", rtype, record["class"], record["ttl"], len(rdata))
        + rdata
    )


def read_name(data, offset: int):
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


def read_record(data, offset: int):
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


def build_flags(rd: int, rcode: int) -> int:
    qr = 1
    ra = 1
    return (qr << 15) | (rd << 8) | (ra << 7) | rcode


def build_dns_response(id: int, rd: int, question: dict, rcode: int, records) -> bytes:
    packed = [pack_record(record) for record in records]
    packed = [item for item in packed if item is not None]

    header = struct.pack("!6H", id, build_flags(rd, rcode), 1, len(packed), 0, 0)
    question_bytes = pack_name(question["name"]) + struct.pack("!HH", question["type"], question["class"])
    return header + question_bytes + b"".join(packed)


def build_dns_req(address: str, qtype: int = QTYPE) -> bytes:
    header = struct.pack("!6H", ID, FLAGS, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT)
    question = pack_name(address) + struct.pack("!HH", qtype, QCLASS)
    return header + question


def unpack_dns_recv(data: bytes):
    id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!6H", data[:12])

    rcode = flags & 0xF
    aa = flags & (1 << 10)
    rd = (flags >> 8) & 1
    offset = 12

    header = {
        "id": id,
        "rcode": rcode,
        "aa": aa,
        "rd": rd,
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