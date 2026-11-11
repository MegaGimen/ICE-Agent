import pytest
from arena.tier_contract import score_tiers


def data():
    axis={'name':'execution','weight':1,'direction':'deduction','tiers':{'none':{'criterion':'no supported active attack','value':0},'severe':{'criterion':'verified attack continues','value':1}}}
    profile={'id':'explicit-test','red':{'base':1,'axes':[axis]},'blue':{'base':1,'axes':[axis]}}
    item={'tier':'severe','criterion':'verified attack continues','reason':'observed process','evidence_ids':['E1']}
    return profile,{'red':{'execution':item.copy()},'blue':{'execution':item.copy()}}


def test_only_agent_selected_tiers_are_mapped():
    p,v=data();assert score_tiers(p,v,{'E1':{}})['roles']['blue']['reward']==0
    v['blue']['execution']['tier']='none'
    v['blue']['execution']['criterion']=p['blue']['axes'][0]['tiers']['none']['criterion']
    assert score_tiers(p,v,{'E1':{}})['roles']['blue']['reward']==1


def test_no_decimal_or_unknown_tier_or_implicit_weight():
    p,v=data();v['blue']['execution']['score']=.8
    with pytest.raises(ValueError):score_tiers(p,v,{'E1':{}})
    p,v=data();v['blue']['execution']['tier']='invented'
    with pytest.raises(ValueError):score_tiers(p,v,{'E1':{}})
    p,v=data();del p['blue']['axes'][0]['weight']
    with pytest.raises(KeyError):score_tiers(p,v,{'E1':{}})
