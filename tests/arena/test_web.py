import json
import socket
import pytest
from arena import web
from arena.llm import OpenAIBlue
from arena.host_blue import HOST_ROLE, HOST_TOOLS


def test_reject_private_and_mixed_dns(monkeypatch):
    for addresses in (['127.0.0.1'], ['169.254.169.254'], ['::1'], ['8.8.8.8','10.0.0.1']):
        monkeypatch.setattr(socket,'getaddrinfo',lambda *a,**k:[(socket.AF_INET,socket.SOCK_STREAM,6,'',(x,443)) for x in addresses])
        with pytest.raises(ValueError):web.public_addresses('example.com',443)


def test_credentials_not_in_evidence_and_replay_offline(tmp_path,monkeypatch):
    monkeypatch.setenv('BRAVE_SEARCH_API_KEY','private-test-key')
    def response(url,headers):
        assert headers['X-Subscription-Token']=='private-test-key'
        return {'status':200,'raw':json.dumps({'web':{'results':[{'title':'Advisory','url':'https://example.org','description':'Evidence'}]}}).encode()}
    monkeypatch.setattr(web,'retrieve',response)
    first=web.WebTools(tmp_path).call('websearch',query='product version advisory')
    assert first['ok']
    assert all(b'private-test-key' not in p.read_bytes() for p in tmp_path.iterdir())
    monkeypatch.setattr(web,'retrieve',lambda *a,**k:pytest.fail('replay accessed network'))
    replay=web.WebTools(tmp_path,mode='replay')
    assert web.WebTools(tmp_path).call('websearch',query='product version advisory')==first
    assert replay.call('websearch',query='product version advisory')==first
    assert not replay.call('websearch',query='absent query')['ok']
    next(tmp_path.glob('*.body')).write_bytes(b'tampered')
    with pytest.raises(ValueError): replay.call('websearch',query='product version advisory')


def test_redirect_is_rechecked_and_auth_not_forwarded(monkeypatch):
    connections=[]
    monkeypatch.setattr(web,'public_addresses',lambda host,port:['8.8.8.8'] if host=='public.example' else (_ for _ in ()).throw(ValueError('private target')))
    class Conn:
        def __init__(self,*a):connections.append(self)
        def request(self,*a,**kw):pass
        def getresponse(self):return self
        status=302
        def getheader(self,key,default=None):return 'https://127.0.0.1/'
        def close(self):pass
    monkeypatch.setattr(web,'PinnedHTTPS',Conn)
    with pytest.raises(ValueError):web.retrieve('https://public.example')
    assert len(connections)==1


def test_html_is_data_and_fetch_is_bounded(tmp_path,monkeypatch):
    monkeypatch.setattr(web,'retrieve',lambda *a,**kw:{'url':'https://example.org','status':200,'content_type':'text/html','truncated':False,'raw':b'<p>advisory</p><script>secret_script()</script>'})
    w=web.WebTools(tmp_path,max_calls=1)
    result=w.call('fetchurl',url='https://example.org')
    assert result['text']=='advisory'
    assert result['trust']=='untrusted_external_data'
    with pytest.raises(ValueError):w.call('fetchurl',url='https://example.org')


def test_host_policy_exposes_tools_without_changing_application_default():
    policy=OpenAIBlue(base_url='https://example.org',model='test',tools=HOST_TOOLS,role=HOST_ROLE)
    assert {'websearch','fetchurl','shell'} <= {x['function']['name'] for x in policy.tools}
    default=OpenAIBlue(base_url='https://example.org',model='test')
    assert 'shell' not in {x['function']['name'] for x in default.tools}
    assert policy.policy_id!=default.policy_id


def test_final_review_runs_once_and_preserves_draft(tmp_path,monkeypatch):
    import asyncio,time
    from arena.storage import Journal
    class Context:
        deadline=time.monotonic()+30
        trajectory=Journal(tmp_path/'trace.jsonl')
        async def call(self,*a,**kw):return {'observed':True}
        def public_brief(self):return {'mission':'test'}
    policy=OpenAIBlue(base_url='https://example.org',model='test',final_review='Check your evidence.',max_turns=4)
    calls=[]
    def generate(messages,timeout):
        calls.append(len(messages))
        if len(calls)==2:assert messages[-1]['content']=='Check your evidence.'
        return {'choices':[{'message':{'role':'assistant','content':'Draft' if len(calls)==1 else 'Corrected'}}]}
    monkeypatch.setattr(policy,'_generate',generate)
    ctx=Context();asyncio.run(policy.run(ctx))
    assert len(calls)==2
    assert len([x for x in ctx.trajectory.rows if x['kind']=='model.output'])==2
    assert len([x for x in ctx.trajectory.rows if x['kind']=='policy.review'])==1


def test_search_retries_rate_limit_without_recording_credentials(tmp_path,monkeypatch):
    monkeypatch.setenv('BRAVE_SEARCH_API_KEY','retry-test-secret')
    monkeypatch.setattr(web.time,'sleep',lambda seconds:None)
    attempts=[]
    def retrieve(*args,**kwargs):
        attempts.append(1)
        return {'status':429,'raw':b'limit','retry_after':'1'} if len(attempts)==1 else {'status':200,'raw':b'{"web":{"results":[]}}'}
    monkeypatch.setattr(web,'retrieve',retrieve)
    assert web.WebTools(tmp_path).call('websearch',query='advisory')['ok']
    assert len(attempts)==2
    assert all(b'retry-test-secret' not in p.read_bytes() for p in tmp_path.iterdir())


def test_truncated_report_requires_complete_followup(tmp_path,monkeypatch):
    import asyncio,time
    from arena.storage import Journal
    class Context:
        deadline=time.monotonic()+30
        trajectory=Journal(tmp_path/'trace.jsonl')
        async def call(self,*a,**kw):return {}
        def public_brief(self):return {}
    p=OpenAIBlue(base_url='https://example.org',model='test',max_output_tokens=4096)
    responses=iter([{'choices':[{'finish_reason':'length','message':{'role':'assistant','content':'unfinished'}}]},
                    {'choices':[{'finish_reason':'stop','message':{'role':'assistant','content':'complete'}}]}])
    monkeypatch.setattr(p,'_generate',lambda *a:next(responses))
    ctx=Context();asyncio.run(p.run(ctx))
    assert len([r for r in ctx.trajectory.rows if r['kind']=='model.output'])==2
    assert any(r['kind']=='policy.truncation' for r in ctx.trajectory.rows)
