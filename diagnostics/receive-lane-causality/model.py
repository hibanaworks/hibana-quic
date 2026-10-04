#!/usr/bin/env python3
"""Source-level model of e75 receive_lane_causality.rs; not Rust verification.
Consumes frozen type aliases; expands only g::{Send,Seq,Route,Par,Roll,Resolve}.
Port uses structural AST instead of marker search: only scopes wholly contained in
current range are visited. This is equivalent for a valid tree emitted by source.rs.
The optimized pre-seed skip is omitted; its empty input cannot gain relay facts.
Message tags/frame labels are ignored because receive causality doesn't inspect them.
"""
from __future__ import annotations
import argparse, copy, hashlib, json, re
from dataclasses import dataclass, field
from pathlib import Path
ROOT=Path(__file__).resolve().parent

@dataclass
class Node:
    kind: str
    children: list = field(default_factory=list)
    sender: int|None = None
    receiver: int|None = None
    message: str = ''
    origin: str = ''
    start: int = 0
    end: int = 0
    lane: int = 0
    alias: str = ''


def split_args(text):
    depth=0; out=[]; begin=0
    for i,c in enumerate(text):
        if c=='<': depth+=1
        elif c=='>': depth-=1
        elif c==',' and depth==0: out.append(text[begin:i].strip());begin=i+1
    tail = text[begin:].strip()
    if tail:
        out.append(tail)
    if any(not arg for arg in out):
        raise ValueError('empty non-trailing generic argument')
    return out

class Parser:
    def __init__(self, paths):
        self.aliases={}; self.roles={}; self.names={}; self.texts={}
        for module,path in paths.items():
            text=path.read_text(); self.texts[module]=text
            # Remove comments, preserving newlines for locations.
            clean=re.sub(r'//[^\n]*','',text)
            depth=0; depths=[]
            for c in clean:
                depths.append(depth)
                if c=='{': depth+=1
                elif c=='}': depth-=1
            for m in re.finditer(r'\b(?:pub\s+)?type\s+(\w+)(?:<([^=;]+)>)?\s*=\s*([^;]+);',clean):
                if depths[m.start()]!=0: continue
                name,args,value=m.groups(); params=split_args(args) if args else []
                self.aliases[module,name]=(params,value,clean.count('\n',0,m.start())+1)
            roles={name:int(v) for name,v in re.findall(r'pub\s+const\s+(\w+)\s*:\s*u8\s*=\s*(\d+)',clean)}
            self.roles[module]=roles
            self.names.update({v:name for name,v in roles.items()})
        self.roles['app'].update({'PREFIX_RX':0,'PREFIX_TLS_RX':1,'PREFIX_TX':2})
    def expand(self,module,expr,path=''):
        expr=expr.strip()
        m=re.fullmatch(r'(g::)?(\w+)(?:<(.*)>)?',expr,re.S)
        if not m: raise ValueError(('unparsed type',module,expr))
        builtin,name,raw=m.groups(); args=split_args(raw) if raw else []
        if builtin:
            if name=='Resolve':return self.expand(module,args[0],path)
            if name=='Send':
                s,t,msg=args
                def role(x):return int(x) if x.isnumeric() else self.roles[module][x]
                return Node('send',sender=role(s),receiver=role(t),message=msg,origin=path)
            kinds={'Seq':'seq','Route':'route','Par':'par','Roll':'roll'}
            return Node(kinds[name],[self.expand(module,arg,path) for arg in args],origin=path)
        params,value,line=self.aliases[module,name]
        if len(params)!=len(args):raise ValueError((name,params,args))
        for k,v in zip(params,args):value=re.sub(r'\b'+k+r'\b',lambda _:v,value)
        # A nested type argument substituted into a trait qualification is kept
        # as opaque message text; no message value influences causal analysis.
        node=self.expand(module,value,f'{module}:{name}:{line}')
        node.alias=name
        return node

def lane_merge(left,right,left_span,right_span,events):
    left_sets=[set() for _ in range(left_span)]
    right_sets=[set() for _ in range(right_span)]
    for ev in events[left.start:left.end]:left_sets[ev.lane].update([ev.sender,ev.receiver])
    for ev in events[right.start:right.end]:right_sets[ev.lane].update([ev.sender,ev.receiver])
    r2l=[None]*right_span;l2r=[None]*left_span
    # Same deterministic ascending-order augmenting-path matching as e75.
    def augment(r,seen):
        for l in range(left_span):
            if l not in seen and left_sets[l].isdisjoint(right_sets[r]):
                seen.add(l)
                occupant=l2r[l]
                if occupant is None or augment(occupant,seen):
                    r2l[r]=l;l2r[l]=r;return True
        return False
    for r in range(right_span):augment(r,set())
    span=left_span;remap={}
    for r,l in enumerate(r2l):
        if l is None:remap[r]=span;span+=1
        else:remap[r]=l
    for ev in events[right.start:right.end]:ev.lane=remap[ev.lane]
    return span

def lower(node,events):
    node.start=len(events)
    if node.kind=='send':
        events.append(node); span=1
    elif node.kind=='roll':span=lower(node.children[0],events)
    else:
        spans=[lower(child,events) for child in node.children]
        span=lane_merge(*node.children,*spans,events) if node.kind=='par' else max(spans)
    node.end=len(events)
    return span

def walk(node):
    yield node
    for child in node.children:yield from walk(child)

def sender_change(earlier,candidate):
    return candidate.sender!=candidate.receiver and earlier.receiver==candidate.receiver and earlier.lane==candidate.lane and earlier.sender!=candidate.sender

class Flow:
    def __init__(self,events,earlier,goal,stop,body_start=0,iteration_start=0):
        self.events=events;self.earlier=earlier;self.goal=goal;self.stop=stop
        self.body_start=body_start;self.iteration_start=iteration_start;self.failures=[]
    def occurrence(self,index):return self.iteration_start+index-self.body_start
    def contains(self,node,occurrence):return self.occurrence(node.start)<=occurrence<self.occurrence(node.end)
    def advance(self,node,facts):
        # Facts are must sets and copied into each arm. For exhaustive reporting,
        # record failure and continue with unchanged semantics, rather than None.
        facts=set(facts)
        if self.occurrence(node.end)<=self.earlier:return facts
        if self.occurrence(node.start)>=self.stop:return facts
        if node.kind=='send':
            occurrence=self.occurrence(node.start)
            if occurrence==self.earlier:facts.add(node.receiver)
            else:
                if occurrence>self.earlier and self.goal is not None and sender_change(self.goal,node) and node.sender not in facts:
                    self.failures.append({'earlier':self.earlier+self.body_start,'later':node.start,'earlier_occurrence':self.earlier,'later_occurrence':occurrence,'known_roles':sorted(facts)})
                if node.sender in facts:facts.add(node.receiver)
            return facts
        if node.kind=='seq':
            for child in node.children:facts=self.advance(child,facts)
            return facts
        if node.kind=='roll':return self.advance(node.children[0],facts)
        left,right=node.children
        # Bulk ReceiveLane and Closure never select a target-containing arm.
        # Route alone selects the arm containing the seed occurrence.
        if node.kind=='route':
            if self.contains(left,self.earlier):return self.advance(left,facts)
            if self.contains(right,self.earlier):return self.advance(right,facts)
        l=self.advance(left,facts);r=self.advance(right,facts)
        return l&r if node.kind=='route' else l|r

def analyze(root):
    events=[];span=lower(root,events)
    structured=[]
    for idx,earlier in enumerate(events):
        candidates=[j+1 for j in range(idx+1,len(events)) if sender_change(earlier,events[j])]
        if earlier.sender==earlier.receiver or not candidates:continue
        f=Flow(events,idx,earlier,max(candidates));f.advance(root,set());structured+=f.failures
    reentry=[]
    for node in walk(root):
        if node.kind!='roll':continue
        for idx in range(node.start,node.end):
            earlier=events[idx]
            candidates=[j+1 for j in range(node.start,node.end) if sender_change(earlier,events[j])]
            if earlier.sender==earlier.receiver or not candidates:continue
            length=node.end-node.start
            first=Flow(events,idx-node.start,None,float('inf'),node.start,0)
            facts=first.advance(node,set())
            second=Flow(events,idx-node.start,earlier,length+max(candidates)-node.start,node.start,length)
            second.advance(node,facts);reentry+=second.failures
    return events,span,structured,reentry

def readable_message(expr):
    expr=re.sub(r'<(\w+) as (ReceivePhase|TransmitPhase)>\s*::\s*(\w+)',lambda m:f'{m[1]}.{m[3]}',expr)
    expr=re.sub(r'<(.+) as Publication>\s*::\s*(\w+)',lambda m:f'{m[1]}.{m[2]}',expr)
    return expr

def describe(ev,names):
    return {'index':ev.start,'from':ev.sender,'from_name':names.get(ev.sender,str(ev.sender)),'to':ev.receiver,'to_name':names.get(ev.receiver,str(ev.receiver)),'message':readable_message(ev.message),'lane':ev.lane,'origin':ev.origin}

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--app',type=Path);parser.add_argument('--prefix',type=Path);parser.add_argument('--output',type=Path,default=ROOT/'result.json');args=parser.parse_args()
    paths={'prefix':args.prefix or ROOT.parents[1]/'src/connection/protocol.rs','app':args.app or ROOT.parents[1]/'src/connection/application/protocol.rs'}
    p=Parser(paths)
    # Exact combined shape in application::programs, not the standalone app Flow.
    root=Node('seq',[p.expand('prefix','Flow'),Node('seq',[p.expand('app','Startup'),p.expand('app','Flow')])])
    events,span,structured,reentry=analyze(root)
    result={'caveat':'Source-level Python model, not a Rust compile, type check, global validator pass, or runtime test. Enumeration continues after a failure; production returns at the first failure.','sha256':{str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path):hashlib.sha256(path.read_bytes()).hexdigest() for path in [*paths.values(),ROOT.parents[1]/'vendor/hibana/src/global/const_dsl/receive_lane_causality.rs']},'events':len(events),'lane_span':span,'structured_failures':[],'roll_reentry_failures':[],'event_rows':[describe(ev,p.names) for ev in events]}
    for key,failures in [('structured_failures',structured),('roll_reentry_failures',reentry)]:
        for f in failures:result[key].append(dict(f,earlier_event=describe(events[f['earlier']],p.names),later_event=describe(events[f['later']],p.names)))
    args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(f'Events={len(events)}, lane_span={span}, structured failed obligations={len(structured)}, roll-reentry failed obligations={len(reentry)}')
    for f in structured+reentry:
        e,c=events[f['earlier']],events[f['later']]
        print(f"[{e.start}] {p.names.get(e.sender,str(e.sender))}->{p.names.get(e.receiver,str(e.receiver))} {readable_message(e.message)} => [{c.start}] {p.names.get(c.sender,str(c.sender))}->{p.names.get(c.receiver,str(c.receiver))} {readable_message(c.message)}; facts={','.join(p.names.get(x,str(x)) for x in f['known_roles'])}")

if __name__=='__main__':main()
