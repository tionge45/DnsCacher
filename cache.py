import json
import os
import datetime


class Cache:
    @staticmethod
    def load() -> dict:
        json_info = {}
        print('Loading the cache...')
        if os.path.exists('cache.txt'):
            with open('cache.txt', 'r') as file:
                for line in file:
                    data = json.loads(line)
                    if Cache.check_ttl(data):
                        origin = data['origin']
                        json_info[origin] = data

        print(f'The cache is loaded. Number of objects: {len(json_info)}')
        return json_info

    @staticmethod
    def save(data) -> None:
        with open(f'cache.txt', 'w') as file:
            for line in data.values():
                json.dump(line, file)
                file.write('\n')

    @staticmethod
    def update(data) -> None:
        while data.check_cache:
            for domain, value in data.cache.copy().items():
                if not Cache.check_ttl(data.cache[domain]):
                    data.cache.pop(domain)
        print('Saving cache...')
        Cache.save(data.cache)

    @staticmethod
    def check_ttl(data: dict) -> bool:
        for qtype, value in data['data'].copy().items():
            for record in value:
                time = datetime.datetime.fromisoformat(data['time'])
                if (datetime.datetime.now() - time).seconds > record['ttl']:
                    value.remove(record)
            if not value:
                data['data'].pop(qtype)
        return bool(data['data'])