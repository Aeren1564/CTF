import json
import hashlib
import secrets

def commitment_from_json(json_str):
    # expected format: [ "<commitment 0>", "<commitment 1>", ... ]
    parse_result = json.loads(json_str)
    assert isinstance(parse_result, list), "Commitment must be a list of digests"
    for entry in parse_result:
        assert isinstance(entry, str), "Commitment must be a string"
    return parse_result

def commitment_to_json(commitment_list):
    assert isinstance(commitment_list, list), "Commitment must be list"
    return json.dumps(commitment_list)


def reveal_from_json(json_str):
    # expected format: [{ "commitment": "<hex digest>", "color_name": "a", "nonce": 1 }, ...]
    parse_result = json.loads(json_str)
    assert isinstance(parse_result, list), "Reveal must be a list of decommitments"
    for entry in parse_result:
        assert isinstance(entry["commitment"], str), "Commitment must be a hex string"
        assert isinstance(entry["color_name"], str), "Color name must be a string"
        assert isinstance(entry["nonce"], int), "Nonce value must be int"
    return parse_result

def reveal_to_json(reveal_list):
    assert isinstance(reveal_list, list), "Reveal must be list"
    return json.dumps(reveal_list)


def verify_commitment(commitment, color_name, nonce):
    # verifies a single reveal entry
    original_data = f"{color_name}-{nonce} and some salt for fun".encode("utf-8")
    m = hashlib.sha256()
    m.update(original_data)
    digest_str = m.hexdigest()
    return commitment == digest_str

def make_reveal_entry(color_name, nonce=None):
    if nonce is None:
        nonce = secrets.randbelow(1000000000000)
    hash_data = f"{color_name}-{nonce} and some salt for fun".encode("utf-8")
    m = hashlib.sha256()
    m.update(hash_data)
    digest_str = m.hexdigest()
    return {
        "commitment": digest_str,
        "color_name": color_name,
        "nonce": nonce
    }
