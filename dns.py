import socket
import datetime
from threading import Thread

from cache import Cache
from parser import Parser, Header, Flags

TRUST_SERVER = '77.88.8.1', 53
PORT = 53
IP = '127.0.0.1'


class DNS:
    question_type = {
        b'\x00\x01': 'a',
        b'\x00\x0c': 'ptr',
        b'\x00\x02': 'ns'
    }

    def __init__(self, cache: dict) -> None:
        self.cache = cache
        self.check_cache = 1

    def make_response(self, data: bytes) -> bytes:
        request_info = Parser.parse_incoming_request(data)
        request_type = request_info['question']['QTYPE']
        current_response = b''

        if request_type in ('a', 'ns'):
            print(f'\nRequest received: type {request_type}')
            current_response = self.build_response(data)

        return current_response

    def build_response(self, data: bytes) -> bytes:
        records, record_type, domain = self.get_records(data[12:])
        header = Header(
            ID=data[0:2],
            FLAGS=self.build_response_flags(data[2:4]),
            ANCOUNT=len(records).to_bytes(2, byteorder='big'),
        ).__bytes__()

        question = self.build_question(domain, record_type)
        body = b''.join([self.record_to_bytes(record_type, record['ttl'], record['value']) for record in records])

        print(f'Request data sent: {domain}')
        print('Waiting for a new request...')

        return header + question + body

    def get_records(self, data) -> tuple[list, str, str]:
        domain, qt = Parser.get_question_domain(data)
        question_type = self.question_type[qt] if qt in self.question_type else ''
        records = b''

        info = self.get_info(domain, question_type)
        if info['data']:
            records = info['data'][question_type]
        else:
            print(f'No data on {domain}')

        return records, question_type, domain

    def build_response_flags(self, flags: bytes) -> bytes:
        first_byte = flags[:1]
        flags = Flags(
            OPCODE=''.join([Parser.get_bit_in_byte(first_byte, bit) for bit in range(1, 5)])
        )
        return \
            self.flags_to_bytes(flags.get_part1()) + self.flags_to_bytes(flags.get_part2())

    @staticmethod
    def flags_to_bytes(*args) -> bytes:
        return int(''.join(args), 2).to_bytes(1, byteorder='big')

    @staticmethod
    def build_question(domain: str, record_type: str) -> bytes:
        question = b''

        for part in domain.split('.'):
            question += bytes([len(part)])
            question += b''.join([ord(char).to_bytes(1, byteorder='big') for char in part])

        if record_type == 'a':
            question += b'\x00\x01'
        elif record_type == 'ns':
            question += b'\x00\x02'

        question += b'\x00\x01'
        return question

    @staticmethod
    def record_to_bytes(record_type: str, ttl: int, value: str) -> bytes:
        record = b'\xc0\x0c'

        if record_type == 'a':
            record += b'\x00\x01'
        elif record_type == 'ns':
            record += b'\x00\x02'

        record += b'\x00\x01'
        record += int(ttl).to_bytes(4, byteorder='big')

        if record_type == 'a':
            record += b'\x00\x04'
            record += b''.join([bytes([int(part)]) for part in value.split('.')])
        elif record_type == 'ns':
            byte_value = bytes(bytearray.fromhex(value))
            record += bytes([0, len(byte_value)]) + byte_value

        return record

    def make_info_from_response(self, data: bytes, domain: str, qtype: str) -> dict:
        question = self.build_question(domain, qtype)
        ancount = int.from_bytes(data[6:8], 'big')
        answer = data[12 + len(question):]

        self.cache[domain] = {
            'origin': domain,
            'time': str(datetime.datetime.now()),
            'data': self.get_records_from_answer(answer, ancount)
        }
        return self.cache[domain]

    @staticmethod
    def make_ipv4_from_bytes(data_bytes: bytes) -> str:
        return '.'.join([str(byte) for byte in data_bytes])

    def get_records_from_answer(self, answer: bytes, count: int) -> dict:
        ptr = 0
        records = {}

        for _ in range(count):
            record = {}
            record_type = int.from_bytes(answer[ptr + 2: ptr + 4], 'big')
            ttl = int.from_bytes(answer[ptr + 6:ptr + 10], 'big')
            record_length = int.from_bytes(answer[ptr + 10: ptr + 12], 'big')
            record_data = ''

            if record_type == 1:
                record_data = self.make_ipv4_from_bytes(answer[ptr + 12:ptr + 12 + record_length])
            elif record_type == 2:
                record_data = answer[ptr + 12:ptr + 12 + record_length].hex()

            ptr += 12 + record_length
            record_type = Parser.make_type_from_number(record_type)
            record['ttl'] = ttl
            record['value'] = record_data

            if record_type in records:
                records[record_type].append(record)
            else:
                records[record_type] = [record]

        return records

    def find_data(self, domain: str, qtype: str) -> dict:
        request = self.build_request(domain, qtype)
        temp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        temp_sock.sendto(request, TRUST_SERVER)
        data, _ = temp_sock.recvfrom(512)
        temp_sock.close()
        info = self.make_info_from_response(data, domain, qtype)
        return info

    def get_info(self, domain: str, qtype: str) -> dict:
        if domain in self.cache:
            info = self.cache[domain]
            if qtype in info['data']:
                print(f'Found in cache: {domain}')
                info = self.cache[domain]
            else:
                print(f'Found in cache: {domain} Missing type: {qtype}. Request...')
                info = self.find_data(domain, qtype)
        else:
            print(f'Not found in cache: {domain} Request...')
            info = self.find_data(domain, qtype)

        return info

    def build_request(self, domain: str, qtype: str) -> bytes:
        header = Header().__bytes__()
        question = self.build_question(domain, qtype)
        return header + question


def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((IP, PORT))
    print(f'Server is running on {IP, PORT} ...')
    try:
        while True:
            client_data, address = server_socket.recvfrom(512)
            response = dns.make_response(client_data)
            server_socket.sendto(response, address)
    except KeyboardInterrupt:
        print('\nServer stopped')
        dns.check_cache = 0
        server_socket.close()


if __name__ == '__main__':
    dns = DNS(Cache.load())
    thread_cache = Thread(target=Cache.update, args=(dns,))
    thread_cache.start()
    main()