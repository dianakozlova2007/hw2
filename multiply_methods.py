from constants import A_CODE, MULTIPLY_LABEL, MULTIPLY_TTL, NOERROR_CODE


def get_numbers(name_parts):
    numbers = []
    for part in name_parts:
        if part == "multiply":
            break

        try:
            number = int(part)
        except (ValueError, TypeError):
            return []
        numbers.append(number)

    return numbers


def multiply(numbers):
    if len(numbers) == 0:
        return None

    result = 1
    for number in numbers:
        result *= number

    return result % 256


def multiply_result(question):
    if question["type"] != A_CODE:
        return None

    parts = question["name"].lower().split(".")
    if MULTIPLY_LABEL not in parts:
        return None

    mul = multiply(get_numbers(parts[: parts.index(MULTIPLY_LABEL)]))
    if mul is None:
        return None

    record = {
        "name": question["name"],
        "type": A_CODE,
        "class": 1,
        "ttl": MULTIPLY_TTL,
        "rdata": f"127.0.0.{mul}",
    }
    return {"rcode": NOERROR_CODE, "records": [record]}