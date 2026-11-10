import json
import subprocess
import sys
from pathlib import Path
from arena import guest_probe


def test_guest_script_executes_and_reports_real_process():
    config={'executables':[str(Path(sys.executable).resolve())],'endpoints':[]}
    got=subprocess.run([sys.executable,'-c',guest_probe.GUEST_SCRIPT,json.dumps(config)],capture_output=True,text=True,check=True)
    result=json.loads(got.stdout)
    assert result['processes']
    assert all(p['cpu_ticks']>=0 and p['start_ticks']>0 for p in result['processes'])


def test_transport_error_is_not_business_failure(monkeypatch):
    monkeypatch.setattr(guest_probe.subprocess,'run',lambda *a,**k:subprocess.CompletedProcess(a,1,'','script failed'))
    result=guest_probe.probe(2296,'key',{})
    assert result['valid'] is False
    assert 'endpoints' not in result
