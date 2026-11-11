"""Current semantic-tier Agent judge; earlier verdicts remain readable for history."""
import asyncio,json
from pathlib import Path
from .tier_judge import VERSION,adjudicate_tiers,load_tier_score
from .host_scoring import file_hash
from .storage import write_json
from .judge_tools import configured_model

async def judge_match(root,port=None,key=None,resume=False):
    return await adjudicate_tiers(root,port,key,resume=resume)

def load_score(root):
    root=Path(root);seal=json.loads((root/'judge_seal.json').read_text())
    if seal.get('mode')=='semantic_tiers':return load_tier_score(root)
    if seal.get('mode')=='impact_review':
        from .impact_judge import load_impact_score
        return load_impact_score(root)
    # Historical verification only: never invoke the old judge to generate new values.
    from .legacy_metric_judge import load_score as historical_score
    return historical_score(root)

if __name__=='__main__':
    import argparse,shutil
    p=argparse.ArgumentParser(description='Agent adjudication; never substitutes a rule score')
    p.add_argument('directory',type=Path);p.add_argument('--port',type=int);p.add_argument('--key',type=Path)
    p.add_argument('--resume',action='store_true');p.add_argument('--revision-out',type=Path)
    args=p.parse_args();root=args.directory
    if args.revision_out:
        source=root.resolve();target=args.revision_out.resolve()
        if source==target or source in target.parents or target in source.parents:p.error('revision must use a separate evidence tree')
        target.mkdir(parents=True,exist_ok=False,mode=0o700);(target/'private').mkdir(mode=0o700)
        names=['match.json','completion.json','outcomes.jsonl','blue_trajectory.jsonl','red_trajectory.jsonl','private/assets.json']
        if args.resume:names.append('judge_trajectory.jsonl')
        for name in names:shutil.copyfile(source/name,target/name)
        if args.resume:
            if (source/'tier_profile.json').exists():shutil.copyfile(source/'tier_profile.json',target/'tier_profile.json')
            for name in ('judge_axes','judge_axis_state','impact_findings','impact_checkpoints','tier_verdicts','tier_checkpoints'):
                if (source/name).exists():shutil.copytree(source/name,target/name)
        write_json(target/'adjudication_parent.json',{'source':str(source),'source_outcome_hash':file_hash(source/'outcomes.jsonl'),'resume':args.resume},private=True)
        root=target
    elif root.with_name(root.name+'.case').exists() or (root/'judge_verdict.json').exists():
        p.error('sealed prior judgment must be preserved; choose --revision-out')
    try:asyncio.run(judge_match(root,args.port,args.key,resume=args.resume))
    except Exception as exc:
        write_json(root/'judge_failure.json',{'error_type':type(exc).__name__,'rule_fallback_used':False},private=True)
        raise
    from .round_scoring import finalize
    print(json.dumps(finalize(root),ensure_ascii=False,indent=2))
