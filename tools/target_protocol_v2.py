"""Independent canonical V2 identity / full-event evaluator (no Rust imports)."""
import hashlib,json,struct

PARAMETERS=dict(parameterVersion='lif-point-v0-dev',timeStepUs=1000,leakDivisor=8,threshold=100,reset=0,membraneLimit=1000000,refractorySteps=2,synapticUnit=1,synapticDelaySteps=1,backgroundProbabilityU16=256,backgroundCurrent=10,observeStart=0,steps=256)
def canonical(x):
    def check(v):
        if isinstance(v,float) or isinstance(v,int) and abs(v)>9007199254740991:raise ValueError('canonical safe integer')
        if isinstance(v,dict):
            for k,a in v.items():
                if not k.isascii():raise ValueError('ASCII keys')
                check(a)
        elif isinstance(v,list):
            for a in v:check(a)
    check(x);return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def sha(b):return hashlib.sha256(b).hexdigest()
def identity(domain,x):return sha(('FlyPoW/'+domain+'/v2\0').encode()+canonical(x))
def seed(pre,entropy,j):
    raw=hashlib.sha256(b'FlyPoW/background-seed/v2\0'+bytes.fromhex(pre)+bytes.fromhex(entropy)+struct.pack('<I',j)).digest()
    return format(struct.unpack('<Q',raw[:8])[0],'016x')
def inputs(g):
    size=len(g["stimulusSet"])
    for k in ["starts","durations","currents"]:size*=len(g["inputDomain"][k])
    if size>1000000:raise ValueError("input domain product bound")
    return [dict(stimulatedBodyId=s['bodyId'],startStep=a,endStep=a+d,current=i) for s in g['stimulusSet'] for a in g['inputDomain']['starts'] for d in g['inputDomain']['durations'] for i in g['inputDomain']['currents'] if a+d+g['windows'][-1]['endOffset']<=g['steps'] and i*d<=g['maxStimulusCost']]
def validate_family(f,g=None):
    fields={'schema','revision','graphRoot','modelRoot','parameterProfileHash','evaluatorVersion','referenceGoalId','preregistrationHash','normalizationVersion','members','levels','limits'}
    canonical(f)
    if set(f)!=fields or f['schema']!='flypow-comparable-difficulty-family-v1' or f['normalizationVersion']!='reference-work-r2-ratio-v1' or f['evaluatorVersion']!='full-events-selective-v1' or not 1<=f['revision']<=0xffffffff:raise ValueError('family version')
    def root(s):
        if not isinstance(s,str) or len(s)!=64 or any(c not in '0123456789abcdef' for c in s):raise ValueError('root')
    for k in ['graphRoot','modelRoot','parameterProfileHash','referenceGoalId','preregistrationHash']:root(f[k])
    if not 2<=len(f['members'])<=128 or not 1<=len(f['levels'])<=4 or any(not isinstance(s,str) for s in f['limits']):raise ValueError('family bounds')
    seen=set()
    for m in f['members']:
        if set(m)!={'goalId','calibrationHash','normalizationNumerator','normalizationDenominator'}:raise ValueError('member fields')
        root(m['goalId']);root(m['calibrationHash'])
        if m['goalId'] in seen or not 1<=m['normalizationNumerator']<=86400000 or not 1<=m['normalizationDenominator']<=86400000:raise ValueError('member bounds')
        seen.add(m['goalId'])
    if f['referenceGoalId'] not in seen or f['levels'][0]!={'requiredBackgrounds':2,'difficultyMicros':1000000}:raise ValueError('reference R2')
    r=d=0
    for l in f['levels']:
        if set(l)!={'requiredBackgrounds','difficultyMicros'} or l['requiredBackgrounds'] not in [2,4,8,16] or l['requiredBackgrounds']<=r or not d<l['difficultyMicros']<=1000000000:raise ValueError('family ordered levels')
        r=l['requiredBackgrounds'];d=l['difficultyMicros']
    if g and (any(f[k]!=g[k] for k in ['graphRoot','modelRoot','parameterProfileHash','evaluatorVersion']) or not any(m['goalId']==identity('goal-id',g) and m['calibrationHash']==g['calibrationHash'] for m in f['members'])):raise ValueError('family science/calibration')
    return f
def validate_family_extension(pre,goal):
    e=pre.get('difficultyPolicy',{}).get('comparableFamily')
    if e is None:return
    if set(e)!={'familyId','descriptor','normalizationNumerator','normalizationDenominator'}:raise ValueError('extension fields')
    f=validate_family(e['descriptor'],goal);m=next(m for m in f['members'] if m['goalId']==pre['goalId'])
    if e['familyId']!=identity('comparable-difficulty-family',f) or any(e[k]!=m[k] for k in ['normalizationNumerator','normalizationDenominator']) or {'requiredBackgrounds':pre['requiredBackgrounds'],'difficultyMicros':pre['difficultyMicros']} not in f['levels']:raise ValueError('frozen family extension')
def validate_round(r):
    p=r['pre'];g=r['goal'];gid=identity('goal-id',g)
    if p['goalId']!=gid or p['goalDefinitionHash']!=gid or any(p[k]!=g[k] for k in ['calibrationHash','inputDomainHash','parameterProfileHash','graphRoot','modelRoot','evaluatorVersion']):raise ValueError('frozen science')
    validate_family_extension(p,g)
    if 'difficultyPolicy' in p and p['difficultyPolicyHash']!=identity('difficulty-policy',p['difficultyPolicy']):raise ValueError('policy hash')
    ph=identity('pre-round',p)
    if r['preRoundSpecHash']!=ph or r['entropySource']!='authority-csprng-dev-v1' or r['seedDerivationVersion']!='sha256-pre-entropy-u32le-u64le-v1' or p['requiredBackgrounds'] not in [2,4,8,16] or not p['requiredBackgrounds']<=len(r['seeds'])<=16:raise ValueError('challenge derivation')
    if r['seeds']!=[seed(ph,r['roundEntropy'],j) for j in range(len(r['seeds']))]:raise ValueError('seed prefix')
    core={k:r[k] for k in ['preRoundSpecHash','roundEntropy','entropySource','seedDerivationVersion','seeds']}
    if r['roundId']!=identity('round-id',core) or r['signedRevision']!=1 or not p['openedAt']<p['claimDeadline']<p['revealDeadline']<p['verificationDeadline'] or p['verificationDeadline']-p['openedAt']>86400:raise ValueError('round identity/deadlines')
    return r
def evaluate(g,x,blob):
    import numpy as np
    target=next(s['modelIndex'] for s in g['stimulusSet'] if s['bodyId']==x['stimulatedBodyId'])
    if blob[:8]!=b'FBRP1\0\0\0' or struct.unpack_from('<III',blob,8)!=(g['neuronCount'],target,g['steps']):raise ValueError('full archive identity')
    a,b=struct.unpack_from('<II',blob,472)
    if len(blob)!=480+8*(a+b) or struct.unpack_from('<QQ',blob,24)!=(a,b):raise ValueError('full archive length/counts')
    events=np.frombuffer(blob,dtype='<u4',offset=480).reshape((-1,2));lanes=[events[:a],events[a:]]
    for lane in lanes:
        if len(lane):
            keys=lane[:,0].astype(np.uint64)*g['neuronCount']+lane[:,1]
            if np.any(lane[:,0]>=g['steps']) or np.any(lane[:,1]>=g['neuronCount']) or np.any(keys[1:]<=keys[:-1]):raise ValueError('event order/range')
    gi=[m['modelIndex'] for m in g['responseSet']];oi=[m['modelIndex'] for m in g['offTargetSet']];metrics=[]
    for w in g['windows']:
        c=[]
        for lane in lanes:
            subset=lane[(lane[:,0]>=x['endStep']+w['startOffset'])&(lane[:,0]<x['endStep']+w['endOffset']),1]
            c.append(np.bincount(subset,minlength=g['neuronCount']).astype(np.int64))
        delta=c[1]-c[0];net=int(delta[gi].sum());positive=int(np.count_nonzero(delta[gi]>0));off=int(np.abs(delta[oi]).sum())
        passed=net>=w['minTargetNet'] and positive>=w['minPositiveCells'] and off<=w['maxOffTarget'] and net>0 and net*w['selectivityDenominator']>=off*w['selectivityNumerator']
        metrics.append(dict(targetNet=net,positiveCells=positive,offTargetAbs=off,passed=passed))
    cost=x['current']*(x['endStep']-x['startStep']);return dict(windows=metrics,stimulusCost=cost,baselineSpikes=a,passed=cost<=g['maxStimulusCost'] and all(m['passed'] for m in metrics))
