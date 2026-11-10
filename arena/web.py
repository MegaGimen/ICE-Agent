"""Controller-side public-web evidence tools; never expose provider credentials to guests."""
from __future__ import annotations
import hashlib
import http.client
from html.parser import HTMLParser
import ipaddress
import json
import os
from pathlib import Path
import socket
import ssl
import time
from urllib.parse import urlencode, urljoin, urlsplit
from .storage import write_json


class Text(HTMLParser):
    def __init__(self):
        super().__init__(); self.parts = []; self.hidden = 0
    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style'): self.hidden += 1
    def handle_endtag(self, tag):
        if tag in ('script', 'style'): self.hidden = max(0, self.hidden - 1)
    def handle_data(self, data):
        if not self.hidden and data.strip(): self.parts.append(data.strip())


def public_addresses(host, port):
    addresses = list(dict.fromkeys(x[4][0] for x in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)))
    if not addresses or any(not ipaddress.ip_address(x).is_global for x in addresses):
        raise ValueError('Public-web tools cannot access private, loopback or reserved addresses')
    return addresses


class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, port, address, timeout):
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self.address = address
    def connect(self):
        raw = socket.create_connection((self.address, self.port), self.timeout)
        try: self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close(); raise


def retrieve(url, headers=None, limit=2_000_000, timeout=15):
    for _ in range(5):
        parsed = urlsplit(url)
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError('Expected a public HTTPS URL without credentials')
        if parsed.port not in (None, 443): raise ValueError('Only HTTPS port 443 is supported')
        host = parsed.hostname.encode('idna').decode('ascii')
        address = public_addresses(host, 443)[0]
        connection = PinnedHTTPS(host, 443, address, timeout)
        try:
            connection.request('GET', (parsed.path or '/') + ('?' + parsed.query if parsed.query else ''),
                               headers={'User-Agent': 'ICE-Research/1.0', 'Accept-Encoding': 'identity', **(headers or {})})
            response = connection.getresponse()
            if response.status in (301,302,303,307,308):
                url = urljoin(url, response.getheader('Location') or '')
                headers = None  # credentials must never be forwarded across a redirect
                continue
            raw = response.read(limit + 1)
            return {'url':url,'status':response.status,'content_type':response.getheader('Content-Type',''),
                    'truncated':len(raw)>limit,'raw':raw[:limit], 'retry_after':response.getheader('Retry-After')}
        finally: connection.close()
    raise ValueError('Too many redirects')


class WebTools:
    names = ('websearch', 'fetchurl')
    def __init__(self, directory, *, mode='live', key_file=None, max_calls=20):
        if mode not in ('live','replay'): raise ValueError('invalid web mode')
        self.directory = Path(directory); self.directory.mkdir(parents=True,exist_ok=True,mode=0o700)
        self.mode, self.calls, self.max_calls = mode, 0, max_calls
        self.last_search = 0.0
        path = Path(key_file or os.environ.get('BRAVE_SEARCH_KEY_FILE', '/root/.config/ice-arena/brave.key'))
        self.key = os.environ.get('BRAVE_SEARCH_API_KEY') or (path.read_text().strip() if path.exists() else '')
    def call(self, name, **args):
        if name not in self.names: raise ValueError('unknown web tool')
        if self.calls >= self.max_calls: raise ValueError('web query budget exhausted')
        self.calls += 1
        if name == 'websearch':
            if set(args) != {'query'} or not isinstance(args['query'],str) or not 0 < len(args['query']) <= 600:
                raise ValueError('query must contain 1 to 600 characters')
        elif set(args) != {'url'} or not isinstance(args['url'],str): raise ValueError('url required')
        request = {'name':name,'arguments':args}
        identity = hashlib.sha256(json.dumps(request,sort_keys=True).encode()).hexdigest()
        path = self.directory / (identity+'.json')
        if self.mode == 'replay' or path.exists():
            if not path.exists(): return {'ok':False,'error':'query absent from frozen evidence snapshot'}
            record=json.loads(path.read_text())
            if record['request'] != request: raise ValueError('replay request mismatch')
            raw = self.directory / (identity+'.body')
            if not raw.exists() or hashlib.sha256(raw.read_bytes()).hexdigest() != record['response_body_sha256']:
                raise ValueError('cached response body integrity check failed')
            return record['result']
        if name == 'websearch':
            if not self.key: raise ValueError('Brave API key is not configured on the controller')
            for attempt in range(3):
                time.sleep(max(0, 1.05 - (time.monotonic()-self.last_search)))
                self.last_search = time.monotonic()
                got=retrieve('https://api.search.brave.com/res/v1/web/search?'+urlencode({'q':args['query'],'count':5}),
                             {'X-Subscription-Token':self.key,'Accept':'application/json'})
                if got['status'] != 429 or attempt == 2: break
                try: delay = min(5, max(1, float(got.get('retry_after') or 2)))
                except ValueError: delay = 2
                time.sleep(delay)
            if got['status'] != 200: result={'ok':False,'status':got['status'],'error':'search provider request failed'}
            else:
                body=json.loads(got['raw'])
                result={'ok':True,'results':[{'title':x.get('title'),'url':x.get('url'),'description':x.get('description')} for x in body.get('web',{}).get('results',[])]}
        else:
            got=retrieve(args['url'])
            content=got['raw'].decode('utf-8',errors='replace')
            if 'html' in got['content_type']:
                parser=Text();parser.feed(content);content='\n'.join(parser.parts)
            elif not any(x in got['content_type'] for x in ('text/','json','xml')):
                content='Unsupported document type; binary was not executed or parsed.'
            result={'ok':got['status']==200, 'url':got['url'],'status':got['status'],
                    'content_type':got['content_type'],'text':content[:28000],
                    'truncated':got['truncated'] or len(content)>28000,
                    'body_sha256':hashlib.sha256(got['raw']).hexdigest()}
        result.update({'retrieved_at':time.time(),'evidence_id':identity,'trust':'untrusted_external_data'})
        record={'request':request,'result':result, 'response_body_sha256':hashlib.sha256(got['raw']).hexdigest()}
        # Preserve the exact received bytes privately; no auth headers are recorded.
        rawpath=self.directory/(identity+'.body')
        fd=os.open(rawpath,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
        with os.fdopen(fd,'wb') as f:f.write(got['raw'])
        write_json(path,record,private=True)
        return result
