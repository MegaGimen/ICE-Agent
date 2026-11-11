"""Explicit tier contracts. No inferred weights and no free-form decimal judgments."""
import math
from .contracts import digest


def validate_profile(profile):
    if not profile.get('id'):raise ValueError('named scoring profile required')
    for role in ('red','blue'):
        axes=profile[role]['axes']
        if not axes:raise ValueError('empty axis set')
        if len({a['name'] for a in axes})!=len(axes):raise ValueError('duplicate axes')
        weights=[]
        for axis in axes:
            weight=axis['weight'];weights.append(weight)
            if type(weight) not in (int,float) or not math.isfinite(weight) or weight<0:raise ValueError('invalid explicit weight')
            if axis['direction'] not in ('credit','deduction'):raise ValueError('explicit direction required')
            if not isinstance(axis['name'],str) or not axis['name']:raise ValueError('axis name required')
            if not axis['tiers']:raise ValueError('explicit tiers required')
            for name,tier in axis['tiers'].items():
                if not isinstance(name,str) or not name or not isinstance(tier['criterion'],str) or not tier['criterion']:raise ValueError('each tier needs its factual criterion')
                value=tier['value']
                if type(value) not in (int,float) or not math.isfinite(value):raise ValueError('invalid tier value')
        if not math.isclose(sum(weights),1,abs_tol=1e-9):raise ValueError('explicit role weights must sum to one')
        if type(profile[role]['base']) not in (int,float) or not math.isfinite(profile[role]['base']):raise ValueError('explicit base required')
    return digest(profile)


def score_tiers(profile,verdict,retrieved):
    """Map Agent-selected labels through the explicitly supplied table; never infer a tier."""
    profile_id=validate_profile(profile);result={'profile_id':profile['id'],'profile_hash':profile_id,'roles':{}}
    for role in ('red','blue'):
        expected={a['name']:a for a in profile[role]['axes']}
        actual=verdict[role]
        if set(actual)!=set(expected):raise ValueError('every configured axis must have an Agent verdict')
        value=profile[role]['base'];rows=[]
        for name,axis in expected.items():
            item=actual[name]
            if any(k in item for k in ('reward','score','loss','value')):raise ValueError('Agent must choose a label, not a decimal score')
            if item['tier'] not in axis['tiers']:raise ValueError('unknown tier')
            if not item.get('criterion') or not item.get('reason'):raise ValueError('criterion and evidence reasoning required')
            if item['criterion']!=axis['tiers'][item['tier']]['criterion']:raise ValueError('quote the selected tier criterion exactly')
            if not item.get('evidence_ids') or any(e not in retrieved for e in item['evidence_ids']):raise ValueError('retrieved evidence references required')
            tier=axis['tiers'][item['tier']]
            amount=axis['weight']*tier['value'];signed=amount if axis['direction']=='credit' else -amount
            value+=signed;rows.append({'axis':name,'tier':item['tier'],'coefficient':tier['value'],'weight':axis['weight'],'direction':axis['direction'],'contribution':signed})
        result['roles'][role]={'reward':value,'axes':rows}
    return result
