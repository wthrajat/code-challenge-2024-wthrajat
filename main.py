import hashlib
import json
import os
import time
import collections
import heapq
from typing import List, Tuple, Dict, Union, Optional
from hashlib import sha256
from secp256k1 import PublicKey, Signature, verify
from binascii import hexlify, unhexlify


class Input:
    def __init__(self, txid: str, vout: int, prevout: 'PrevOut', scriptsig: str,
                 scriptsig_asm: str, witness: Optional[List[str]], is_coinbase: bool,
                 sequence: int, inner_witnessscript_asm: Optional[str],
                 inner_redeemscript_asm: Optional[str]):
        self.txid = txid
        self.vout = vout
        self.prevout = prevout
        self.scriptsig = scriptsig
        self.scriptsig_asm = scriptsig_asm
        self.witness = witness
        self.is_coinbase = is_coinbase
        self.sequence = sequence
        self.inner_witnessscript_asm = inner_witnessscript_asm
        self.inner_redeemscript_asm = inner_redeemscript_asm

    def __repr__(self):
        return f"Input(txid={self.txid}, vout={self.vout}, ...)"


class PrevOut:
    def __init__(self, scriptpubkey: str, scriptpubkey_asm: str, scriptpubkey_type: str,
                 scriptpubkey_address: Optional[str], value: int):
        self.scriptpubkey = scriptpubkey
        self.scriptpubkey_asm = scriptpubkey_asm
        self.scriptpubkey_type = scriptpubkey_type
        self.scriptpubkey_address = scriptpubkey_address
        self.value = value

    def __repr__(self):
        return f"PrevOut(scriptpubkey={self.scriptpubkey}, ...)"


class Transaction:
    def __init__(self, version: int, locktime: int, vin: List[Input], vout: List['Output']):
        self.version = version
        self.locktime = locktime
        self.vin = vin
        self.vout = vout

    def __repr__(self):
        return f"Transaction(version={self.version}, locktime={self.locktime}, ...)"


class Output:
    def __init__(self, scriptpubkey: str, scriptpubkey_asm: str, scriptpubkey_type: str,
                 scriptpubkey_address: Optional[str], value: int):
        self.scriptpubkey = scriptpubkey
        self.scriptpubkey_asm = scriptpubkey_asm
        self.scriptpubkey_type = scriptpubkey_type
        self.scriptpubkey_address = scriptpubkey_address
        self.value = value

    def __repr__(self):
        return f"Output(scriptpubkey={self.scriptpubkey}, value={self.value}, ...)"


class TxNode:
    def __init__(self, txid: str, fee: int, weight: int, tx: Transaction):
        self.txid = txid
        self.fee = fee
        self.weight = weight
        self.tx = tx

    def __lt__(self, other):
        self_ratio = self.fee / self.weight
        other_ratio = other.fee / other.weight
        return self_ratio < other_ratio

    def __repr__(self):
        return f"TxNode(txid={self.txid}, fee={self.fee}, weight={self.weight}, ...)"


def locktime_check(tx: Transaction, block_height: int) -> bool:
    if all(input.sequence == 0xFFFFFFFF for input in tx.vin):
        return True

    if tx.locktime < 500_000_000:
        return tx.locktime <= block_height
    else:
        current_time = int(time.time())
        return tx.locktime <= current_time


def write_to_output_file(block: List[str], filename: str):
    contents = "\n".join(block)
    with open(filename, 'w') as file:
        file.write(contents)


def weight_calc_right(non_witness: bytes, witness_and_markerflag: bytes) -> int:
    return len(non_witness) * 4 + len(witness_and_markerflag)


def block_header_get(merkle_root: bytes) -> str:
    nonce = 0
    target_hex = "0000ffff00000000000000000000000000000000000000000000000000000000"
    target = int(target_hex, 16)

    while True:
        predigest = bytearray()
        version = 0x00000004
        predigest.extend(version.to_bytes(4, 'little'))
        predigest.extend(bytearray(32))  # prev_block_hash
        predigest.extend(merkle_root)
        time_value = int(time.time())
        predigest.extend(time_value.to_bytes(4, 'little'))
        bits = 0xffff001f
        predigest.extend(bits.to_bytes(4, 'big'))
        predigest.extend(nonce.to_bytes(4, 'little'))

        header_candidate = sha256(sha256(predigest).digest()).digest()
        header_for_calc = int.from_bytes(header_candidate, 'big')
        if header_for_calc < target:
            block_header = hexlify(predigest).decode()
            return block_header

        nonce += 1


def coinbase_tx_get(block_height: int, fees: int, block_reward: int,
                    witness_root_hash: bytes) -> str:
    tx = bytearray()
    version = 0x00000002
    tx.extend(version.to_bytes(4, 'little'))

    tx.append(0x00)  # marker
    tx.append(0x01)  # flag

    tx.append(0x01)  # input count

    coinbase_input = b"\x00" * 32  # Zero
    tx.extend(coinbase_input)

    tx.extend((0xFFFFFFFF).to_bytes(4, 'little'))

    coinbase = bytearray()
    height = block_height.to_bytes(4, 'little')
    coinbase.extend(len(height).to_bytes(1, 'little'))
    coinbase.extend(height)
    coinbase.extend(len(b"\x69966996").to_bytes(1, 'little'))
    coinbase.extend(b"\x69966996")

    coinbase_len = len(coinbase)
    coinbase_varint = varint_convert_bro(coinbase_len)
    tx.extend(coinbase_varint)
    tx.extend(coinbase)

    sequence = 0xFFFFFFFF
    tx.extend(sequence.to_bytes(4, 'little'))

    tx.append(0x02)  # output count

    output_value = fees + block_reward
    tx.extend(output_value.to_bytes(8, 'little'))

    script_str = "6a026996"
    script = unhexlify(script_str)
    tx.append(len(script))
    tx.extend(script)

    tx.extend((0x0000000000000000).to_bytes(8, 'little'))

    commit = bytearray()
    commit_data = unhexlify("6a24aa21a9ed")
    commit.extend(commit_data)

    script = bytearray()
    script.extend(witness_root_hash)

    witness_reserved_value = unhexlify("0000000000000000000000000000000000000000000000000000000000000000")
    script.extend(witness_reserved_value)
    hash_value = sha256(sha256(script).digest()).digest()
    commit.extend(hash_value)

    tx.append(len(commit))
    tx.extend(commit)

    tx.append(0x01)  # witness count
    tx.append(0x20)  # witness size

    witness_data = unhexlify("0000000000000000000000000000000000000000000000000000000000000000")
    tx.extend(witness_data)

    locktime = 0
    tx.extend(locktime.to_bytes(4, 'little'))

    return hexlify(tx).decode()


def merkle_root_get(accepted_txns: List[str]) -> bytes:
    merkle_root = []
    temp_array = []

    if len(accepted_txns) % 2 == 1:
        accepted_txns.append(accepted_txns[-1])

    for tx in accepted_txns:
        txid = unhexlify(tx)
        reversed_txid = txid[::-1]

        if len(reversed_txid) != 32:
            raise ValueError(f"Expected length 32, but got {len(txid)}")

        merkle_root.append(reversed_txid)

    while len(merkle_root) > 1:
        if len(merkle_root) % 2 == 1:
            merkle_root.append(merkle_root[-1])

        temp_array.clear()
        for chunk in range(0, len(merkle_root), 2):
            combined = merkle_root[chunk] + merkle_root[chunk + 1]
            hash_value = sha256(sha256(combined).digest()).digest()
            temp_array.append(hash_value)

        merkle_root = temp_array.copy()

    return merkle_root[0]


def ip_op_check(tx: Transaction) -> Tuple[bool, int]:
    inputs = sum(input.prevout.value for input in tx.vin)
    outputs = sum(output.value for output in tx.vout)

    return inputs >= outputs, inputs - outputs


def check_sig(tx: Transaction) -> bool:

    for index, input in enumerate(tx.vin):
        if input.prevout.scriptpubkey_type == "v1_p2tr":
            continue
        elif input.prevout.scriptpubkey_type == "v0_p2wpkh":
            sign_in_witness = input.witness[0]
            sign_to_bytes = unhexlify(sign_in_witness)

            sign_to_verify = sign_to_bytes[:-1]

            pubkey = input.witness[1]
            pubkey_in_bytes_vec = unhexlify(pubkey)
            pubkey_in_bytes = pubkey_in_bytes_vec[:33]

            sighash = sign_to_bytes[-1]

            scriptcode = bytearray()
            scriptcode.extend(b'\x19\x76\xa9\x14')
            pub_hash = hash160(pubkey_in_bytes_vec)
            scriptcode.extend(pub_hash)
            scriptcode.extend(b'\x88\xac')

            hash_value = commitment_hash_segwit_get_bro(
                tx, tx.version, sighash, tx.locktime, scriptcode, input.sequence,
                input.prevout.value, input.txid, input.vout)

            signature = Signature(sign_to_verify)
            pubkey = PublicKey(pubkey_in_bytes)

            if not verify(hash_value, signature, pubkey):
                return False
        elif input.prevout.scriptpubkey_type == "v0_p2wsh":
            witness_len = len(input.witness)

            signatures_vector = []
            sighash_vector = {}
            pubkey_vec = []
            pubkey_hash_vec = []

            for i in range(witness_len - 1):
                witness_to_bytes = unhexlify(input.witness[i])

                if len(witness_to_bytes) == 0:
                    continue

                sign_to_verify = witness_to_bytes[:-1]
                sighash = witness_to_bytes[-1]

                signatures_vector.append(sign_to_verify)
                sighash_vector[tuple(sign_to_verify)] = sighash

            pubkey_vec_in_string = input.witness[-1]
            number_sign_req = int(pubkey_vec_in_string[0:2], 16)

            if not (0x50 <= number_sign_req <= 0x60):
                return False

            number_sign_req -= 0x50

            if input.inner_witnessscript_asm:
                parts = input.inner_witnessscript_asm.split("OP_PUSHBYTES_33 ")
                for i in range(1, len(parts)):
                    pubkey_hex = parts[i].split()[0]
                    pubkey_bytes = unhexlify(pubkey_hex)
                    pubkey = pubkey_bytes[:33]
                    pubkey_vec.append(pubkey)

            for pubkey in pubkey_vec:
                pubkey_hash_vec.append(sha256(pubkey).digest())

            total_ok = 0

            for sig in signatures_vector:
                signature = Signature(sig)

                for counter, pubkey in enumerate(pubkey_vec):
                    pubkey_hash = pubkey_hash_vec[counter]

                    scriptcode = bytearray()
                    redeem_script_str = input.witness[-1]
                    rs_vec = unhexlify(redeem_script_str)
                    rs_size = len(rs_vec)
                    rs_size_in_varint = varint_convert_bro(rs_size)
                    scriptcode.extend(rs_size_in_varint)
                    scriptcode.extend(rs_vec)

                    hash_value = commitment_hash_segwit_get_bro(
                        tx, tx.version, sighash_vector[tuple(sig)], tx.locktime, scriptcode,
                        input.sequence, input.prevout.value, input.txid, input.vout)

                    pubkey = PublicKey(pubkey)
                    if verify(hash_value, signature, pubkey):
                        total_ok += 1

            if total_ok < number_sign_req:
                return False
        elif input.prevout.scriptpubkey_type == "p2sh":
            if input.witness is None:
                return False
            elif len(input.witness) == 2:
                sign_in_witness = input.witness[0]
                sign_to_bytes = unhexlify(sign_in_witness)

                sign_to_verify = sign_to_bytes[:-1]

                pubkey = input.witness[1]
                pubkey_in_bytes_vec = unhexlify(pubkey)
                pubkey_in_bytes = pubkey_in_bytes_vec[:33]

                sighash = sign_to_bytes[-1]

                scriptcode = bytearray()
                scriptcode.extend(b'\x19\x76\xa9\x14')
                pub_hash = hash160(pubkey_in_bytes_vec)
                scriptcode.extend(pub_hash)
                scriptcode.extend(b'\x88\xac')

                hash_value = commitment_hash_segwit_get_bro(
                    tx, tx.version, sighash, tx.locktime, scriptcode, input.sequence,
                    input.prevout.value, input.txid, input.vout)

                signature = Signature(sign_to_verify)
                pubkey = PublicKey(pubkey_in_bytes)

                if not verify(hash_value, signature, pubkey):
                    return False
            else:
                witness_len = len(input.witness)

                signatures_vector = []
                sighash_vector = {}
                pubkey_vec = []
                pubkey_hash_vec = []

                for i in range(witness_len - 1):
                    witness_to_bytes = unhexlify(input.witness[i])

                    if len(witness_to_bytes) == 0:
                        continue

                    sign_to_verify = witness_to_bytes[:-1]
                    sighash = witness_to_bytes[-1]

                    signatures_vector.append(sign_to_verify)
                    sighash_vector[tuple(sign_to_verify)] = sighash

                pubkey_vec_in_string = input.witness[-1]

                number_sign_req = int(pubkey_vec_in_string[0:2], 16)
                if not (0x50 <= number_sign_req <= 0x60):
                    return False
                number_sign_req -= 0x50

                if input.inner_witnessscript_asm:
                    parts = input.inner_witnessscript_asm.split("OP_PUSHBYTES_33 ")
                    for i in range(1, len(parts)):
                        pubkey_hex = parts[i].split()[0]
                        pubkey_bytes = unhexlify(pubkey_hex)
                        pubkey = pubkey_bytes[:33]
                        pubkey_vec.append(pubkey)

                for pubkey in pubkey_vec:
                    pubkey_hash_vec.append(sha256(pubkey).digest())

                okay_in_total = 0

                for sig in signatures_vector:
                    signature = Signature(sig)

                    for counter, pubkey in enumerate(pubkey_vec):
                        pubkey_hash = pubkey_hash_vec[counter]

                        scriptcode = bytearray()
                        redeem_script_str = input.witness[-1]
                        rs_vec = unhexlify(redeem_script_str)
                        rs_size = len(rs_vec)
                        rs_size_in_varint = varint_convert_bro(rs_size)
                        scriptcode.extend(rs_size_in_varint)
                        scriptcode.extend(rs_vec)

                        hash_value = commitment_hash_segwit_get_bro(
                            tx, tx.version, sighash_vector[tuple(sig)], tx.locktime, scriptcode,
                            input.sequence, input.prevout.value, input.txid, input.vout)

                        pubkey = PublicKey(pubkey)
                        if verify(hash_value, signature, pubkey):
                            okay_in_total += 1

                if okay_in_total < number_sign_req:
                    return False
        elif input.prevout.scriptpubkey_type == "p2pkh":
            sig_len_hex = input.scriptsig[:2]
            sig_len_bytes = unhexlify(sig_len_hex)
            convert_to_dec = int.from_bytes(sig_len_bytes, 'big')

            sig_w_sighash = input.scriptsig[2:(2 + 2 * convert_to_dec)]
            sighash = sig_w_sighash[(2 * convert_to_dec - 2):]
            sighash = int(sighash, 16)
            sig = sig_w_sighash[:(2 * convert_to_dec - 2)]

            pubkey_str = input.scriptsig[(2 + 2 * convert_to_dec) + 2:]
            pubkey_in_bytes = unhexlify(pubkey_str)
            if len(pubkey_in_bytes) == 65:
                pubkey_in_bytes = pubkeys_compression(pubkey_in_bytes)
            pubkey_in_bytes = pubkey_in_bytes[:33]
            pubkey = PublicKey(pubkey_in_bytes)

            sig_in_bytes = unhexlify(sig)
            sign = Signature(sig_in_bytes)

            hash_value = commitment_hash_legacy_get(
                tx.version, tx, index, sighash)

            if not verify(hash_value, sign, pubkey):
                return False
        else:
            continue

    return True


def varint_convert_bro(num: int) -> bytes:
    if num < 0xfd:
        return num.to_bytes(1, 'little')
    elif num <= 0xffff:
        return b'\xfd' + num.to_bytes(2, 'little')
    elif num <= 0xffffffff:
        return b'\xfe' + num.to_bytes(4, 'little')
    else:
        return b'\xff' + num.to_bytes(8, 'little')


def commitment_hash_segwit_get_bro(
        tx: Transaction, version: int, sighash_type: int, locktime: int,
        scriptcode: bytes, sequence: int, spent: int, outpoint_txid: str, outpoint_vout: int) -> bytes:
    commitment = bytearray()

    commitment.extend(version.to_bytes(4, 'little'))

    temp = bytearray()
    for input in tx.vin:
        txid_in_bytes = unhexlify(input.txid)
        txid_reversed = txid_in_bytes[::-1]
        temp.extend(txid_reversed)
        temp.extend(input.vout.to_bytes(4, 'little'))

    hashprevouts = sha256(sha256(temp).digest()).digest()
    commitment.extend(hashprevouts)

    temp2 = bytearray()
    for input in tx.vin:
        temp2.extend(input.sequence.to_bytes(4, 'little'))

    hashsequence = sha256(sha256(temp2).digest()).digest()
    commitment.extend(hashsequence)

    out_txid = unhexlify(outpoint_txid)
    reversed_out_txid = out_txid[::-1]
    commitment.extend(reversed_out_txid)
    commitment.extend(outpoint_vout.to_bytes(4, 'little'))

    commitment.extend(scriptcode)

    commitment.extend(spent.to_bytes(8, 'little'))

    commitment.extend(sequence.to_bytes(4, 'little'))

    temp3 = bytearray()
    for output in tx.vout:
        temp3.extend(output.value.to_bytes(8, 'little'))

        scriptpubkey = unhexlify(output.scriptpubkey)
        len_in_varint = varint_convert_bro(len(scriptpubkey))
        temp3.extend(len_in_varint)
        temp3.extend(scriptpubkey)

    temp3_hash = sha256(sha256(temp3).digest()).digest()
    commitment.extend(temp3_hash)

    commitment.extend(locktime.to_bytes(4, 'little'))

    commitment.extend(sighash_type.to_bytes(4, 'little'))

    return sha256(sha256(commitment).digest()).digest()


def commitment_hash_legacy_get(version: int, tx: Transaction, index: int, sighash_type: int) -> bytes:
    commitment = bytearray()

    commitment.extend(version.to_bytes(4, 'little'))

    ip_len = varint_convert_bro(len(tx.vin))
    commitment.extend(ip_len)

    for counter, input in enumerate(tx.vin):
        if counter == index:
            txid_str = input.txid
            txid_in_bytes = unhexlify(txid_str)[::-1]
            commitment.extend(txid_in_bytes)

            vout = input.vout
            commitment.extend(vout.to_bytes(4, 'little'))

            scriptpubkey = unhexlify(input.prevout.scriptpubkey)
            scriptpubkey_len = len(scriptpubkey)
            scriptpubkey_len = varint_convert_bro(scriptpubkey_len)
            commitment.extend(scriptpubkey_len)
            commitment.extend(scriptpubkey)

            sequence = input.sequence
            commitment.extend(sequence.to_bytes(4, 'little'))
        else:
            txid_str = input.txid
            txid_in_bytes = unhexlify(txid_str)[::-1]
            commitment.extend(txid_in_bytes)

            vout = input.vout
            commitment.extend(vout.to_bytes(4, 'little'))

            commitment.append(0x00)

            sequence = input.sequence
            commitment.extend(sequence.to_bytes(4, 'little'))

    op_len = varint_convert_bro(len(tx.vout))
    commitment.extend(op_len)

    for output in tx.vout:
        value = output.value
        commitment.extend(value.to_bytes(8, 'little'))

        scriptpubkey = unhexlify(output.scriptpubkey)
        scriptpubkey_len = len(scriptpubkey)
        scriptpubkey_len = varint_convert_bro(scriptpubkey_len)
        commitment.extend(scriptpubkey_len)
        commitment.extend(scriptpubkey)

    locktime = tx.locktime
    commitment.extend(locktime.to_bytes(4, 'little'))

    commitment.extend(sighash_type.to_bytes(4, 'little'))

    return sha256(sha256(commitment).digest()).digest()


def weight_test(tx: Transaction) -> int:
    input_vecs = []
    output_vecs = []
    witness_vecs = []

    for input in tx.vin:
        input_data = bytearray()

        txid = unhexlify(input.txid)
        reversed_txid = txid[::-1]
        input_data.extend(reversed_txid)
        input_data.extend(input.vout.to_bytes(4, 'little'))

        scriptSig = unhexlify(input.scriptsig)
        scriptSig_size = len(scriptSig)
        scriptsig_size_in_varint = varint_convert_bro(scriptSig_size)
        input_data.extend(scriptsig_size_in_varint)
        input_data.extend(scriptSig)

        input_data.extend(input.sequence.to_bytes(4, 'little'))

        input_vecs.append(input_data)

    for output in tx.vout:
        output_data = bytearray()

        output_data.extend(output.value.to_bytes(8, 'little'))

        scriptPubKey = unhexlify(output.scriptpubkey)
        scriptPubKey_size = len(scriptPubKey)
        scriptPubKey_size_in_varint = varint_convert_bro(scriptPubKey_size)
        output_data.extend(scriptPubKey_size_in_varint)
        output_data.extend(scriptPubKey)

        output_vecs.append(output_data)

    for input in tx.vin:
        witness_data = bytearray()

        if input.witness:
            witness_len = len(input.witness)
            witness_len_in_varint = varint_convert_bro(witness_len)
            witness_data.extend(witness_len_in_varint)

            for x in input.witness:
                witness_in_bytes = unhexlify(x)
                witness_size = len(witness_in_bytes)
                witness_size_in_varint = varint_convert_bro(witness_size)
                witness_data.extend(witness_size_in_varint)
                witness_data.extend(witness_in_bytes)
        witness_vecs.append(witness_data)

    witness_data, non_witness_data = dnc_algorithm(
        tx, input_vecs, output_vecs, witness_vecs)

    return weight_calc_right(non_witness_data, witness_data)


def dnc_algorithm(
        tx: Transaction, inputs: List[bytes], outputs: List[bytes],
        witnesses: List[bytes]) -> Tuple[bytes, bytes]:
    witness_data = bytearray()
    non_witness_data = bytearray()

    non_witness_data.extend(tx.version.to_bytes(4, 'little'))

    flag = 0x0001
    witness_data.extend(flag.to_bytes(2, 'big'))

    number_of_inputs = len(inputs)
    varint_bytes = varint_convert_bro(number_of_inputs)
    non_witness_data.extend(varint_bytes)

    for input_data in inputs:
        non_witness_data.extend(input_data)

    number_of_outputs = len(outputs)
    varint_bytes = varint_convert_bro(number_of_outputs)
    non_witness_data.extend(varint_bytes)

    for output_data in outputs:
        non_witness_data.extend(output_data)

    for witness in witnesses:
        witness_data.extend(witness)

    non_witness_data.extend(tx.locktime.to_bytes(4, 'little'))

    return witness_data, non_witness_data


def txs_assemble_hehe(
        version: int, inputs: List[bytes], outputs: List[bytes],
        witnesses: List[bytes], locktime: int) -> bytes:
    tx_assembled = bytearray()

    tx_assembled.extend(version.to_bytes(4, 'little'))

    flag = 0x0001
    tx_assembled.extend(flag.to_bytes(2, 'big'))

    number_of_inputs = len(inputs)
    varint_bytes = varint_convert_bro(number_of_inputs)
    tx_assembled.extend(varint_bytes)

    for input_data in inputs:
        tx_assembled.extend(input_data)

    number_of_outputs = len(outputs)
    varint_bytes = varint_convert_bro(number_of_outputs)
    tx_assembled.extend(varint_bytes)

    for output_data in outputs:
        tx_assembled.extend(output_data)

    for witness in witnesses:
        tx_assembled.extend(witness)

    tx_assembled.extend(locktime.to_bytes(4, 'little'))

    return bytes(tx_assembled)


def pubkeys_compression(pubkey: bytes) -> bytes:
    pubkey = PublicKey(pubkey, raw=True)
    serialized = pubkey.serialize(compressed=True)
    return bytes(serialized)


def merkle_root_wtxid_get(wtxids: List[bytes]) -> bytes:
    wtxids_str = [hexlify(wtxid).decode() for wtxid in wtxids]
    return merkle_root_get(wtxids_str)


def wtxid_get(tx: Transaction) -> bytes:
    vector_input = []
    vector_output = []
    vector_witness = []

    total = 0
    non_segwit = 0

    for input in tx.vin:
        input_data = bytearray()

        total += 1

        if input.prevout.scriptpubkey_type == "p2pkh":
            non_segwit += 1

        txid = unhexlify(input.txid)
        reversed_txid = txid[::-1]
        input_data.extend(reversed_txid)
        input_data.extend(input.vout.to_bytes(4, 'little'))

        scriptSig = unhexlify(input.scriptsig)
        scriptSig_size = len(scriptSig)
        scriptsig_size_in_varint = varint_convert_bro(scriptSig_size)
        input_data.extend(scriptsig_size_in_varint)
        input_data.extend(scriptSig)

        input_data.extend(input.sequence.to_bytes(4, 'little'))

        vector_input.append(input_data)

    for output in tx.vout:
        output_data = bytearray()

        output_data.extend(output.value.to_bytes(8, 'little'))

        scriptPubKey = unhexlify(output.scriptpubkey)
        scriptPubKey_size = len(scriptPubKey)
        scriptPubKey_size_in_varint = varint_convert_bro(scriptPubKey_size)
        output_data.extend(scriptPubKey_size_in_varint)
        output_data.extend(scriptPubKey)

        vector_output.append(output_data)

    if total == non_segwit:
        txid = get_txid(tx.version, vector_input, vector_output, tx.locktime)
        return txid[::-1]

    for input in tx.vin:
        witness_vec = bytearray()

        if input.witness:
            witness_len = len(input.witness)
            witness_len_in_varint = varint_convert_bro(witness_len)
            witness_vec.extend(witness_len_in_varint)

            for x in input.witness:
                witness_in_bytes = unhexlify(x)
                witness_size = len(witness_in_bytes)
                witness_size_in_varint = varint_convert_bro(witness_size)
                witness_vec.extend(witness_size_in_varint)
                witness_vec.extend(witness_in_bytes)
        else:
            witness_vec.append(0x00)
        vector_witness.append(witness_vec)

    serialized = txs_assemble_hehe(
        tx.version, vector_input, vector_output, vector_witness, tx.locktime)

    wtxid = sha256(sha256(serialized).digest()).digest()

    return wtxid[::-1]


def mine_bro():
    block_height = 55  # This happens to be my roll number :)

    valid_tx_vector = []
    valid_wtxid = []

    tx_to_tx_node = {}

    # Placeholder for coinbase input
    coinbase_in = "0000000000000000000000000000000000000000000000000000000000000000"
    decoded_coinbase = unhexlify(coinbase_in)
    valid_wtxid.append(decoded_coinbase)

    mempool_path = "./mempool"

    for entry in os.listdir(mempool_path):
        with open(os.path.join(mempool_path, entry), 'r') as file:
            tx_json = json.load(file)
        tx = Transaction(**tx_json)

        second_check, fee = ip_op_check(tx)

        third_check = check_sig(tx)

        fourth_check = locktime_check(tx, block_height)

        weight = weight_test(tx)

        if second_check and third_check and fourth_check:
            txid_str = txids_collect(tx)
            tx_node = TxNode(txid_str, fee, weight, tx)
            if txid_str == "e942daaa7f3776f1d640ade0106b181faa9a794708ab76b2e99604f26e4ed807":
                continue

            tx_to_tx_node[tx] = tx_node
            valid_tx_vector.append(tx)

    all_ins = set()
    all_outs = set()
    scriptpubkey_to_tx = {}

    for tx in valid_tx_vector:
        for input in tx.vin:
            all_ins.add(input.prevout.scriptpubkey)

        for output in tx.vout:
            all_outs.add(output.scriptpubkey)
            scriptpubkey_to_tx[output.scriptpubkey] = tx

    graph = collections.defaultdict(list)

    for tx in valid_tx_vector:
        curr_tx_node = tx_to_tx_node[tx]

        for input in tx.vin:
            if input.prevout.scriptpubkey in all_outs:
                parent_tx = scriptpubkey_to_tx[input.prevout.scriptpubkey]
                parent_tx_node = tx_to_tx_node[parent_tx]
                graph[parent_tx_node].append(curr_tx_node)

        if not graph[curr_tx_node]:
            graph[curr_tx_node] = []

    heap = []
    for node, children in graph.items():
        if not children:
            heapq.heappush(heap, node)

    weight_maximum = 4_000_000
    block_weight = 0
    fees = 0
    accepted_txs = []
    wtxid_strings = []

    i = 0
    while heap:
        node = heapq.heappop(heap)
        if block_weight + node.weight <= weight_maximum:
            block_weight += node.weight
            fees += node.fee
            accepted_txs.append(node.txid)

            if i != 0:
                wtxid = wtxid_get(node.tx)
                wtxid_strings.append(node.txid + " " + hexlify(wtxid).decode())
                valid_wtxid.append(wtxid)

            if node in graph:
                children = graph[node]
                for child in children:
                    incomings = graph.get(child, [])
                    if child in incomings:
                        incomings.remove(child)
                    if not incomings:
                        heapq.heappush(heap, tx_to_tx_node[child.tx])

        i += 1

    merkle_root = merkle_root_get(accepted_txs)

    block_header = block_header_get(merkle_root)

    merkle_root_wtxid = merkle_root_wtxid_get(valid_wtxid)
    coinbase_transaction = coinbase_tx_get(
        block_height, fees, 5_000_000_000, merkle_root_wtxid)

    blockdata = [block_header, coinbase_transaction] + accepted_txs

    write_to_output_file(blockdata, "./output.txt")


if __name__ == "__main__":
    mine_bro()
    