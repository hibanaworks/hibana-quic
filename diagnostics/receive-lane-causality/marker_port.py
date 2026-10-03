"""Literal marker/range port of CausalFlow.advance, for cross-checking AST model.
Only evidence-relevant fields copied. Scope insertion follows eff_list.rs exactly.
The sole diagnostic extension collects every failed obligation instead of None.
"""
from dataclasses import dataclass, replace
from model import sender_change

@dataclass
class Marker:
    offset:int
    end:int
    ordinal:int
    kind:str
    event:str
    boundary:int|None=None
    @property
    def enter(self):return self.event in ('primary','continuation')


def markers_for(root):
    markers=[];ordinal=0
    def insert(m):
        idx=len(markers)
        while idx>0:
            prev=markers[idx-1]
            enter_precedes_equal=m.enter and prev.offset==m.offset and (prev.event=='split' or (prev.enter and prev.ordinal>m.ordinal))
            if prev.offset>m.offset or enter_precedes_equal:idx-=1
            else:break
        markers.insert(idx,m)
    def emit(node):
        nonlocal ordinal
        own=None
        if node.kind in ('route','par','roll'):own=ordinal;ordinal+=1
        for child in node.children:emit(child)
        if own is None:return
        start,end=node.start,node.end
        if node.kind=='route':
            split=node.children[1].start
            insert(Marker(start,split,own,'route','primary',end))
            insert(Marker(split,split,own,'route','exit'))
            insert(Marker(split,end,own,'route','continuation'))
            insert(Marker(end,end,own,'route','exit'))
        elif node.kind=='par':
            split=node.children[1].start
            insert(Marker(start,end,own,'par','primary',split))
            insert(Marker(split,split,own,'par','split'))
            insert(Marker(end,end,own,'par','exit'))
        else:
            insert(Marker(start,end,own,'roll','primary'))
            insert(Marker(end,end,own,'roll','exit'))
    emit(root)
    return markers

@dataclass
class Range:
    start:int
    end:int
    floor:int=0

class MarkerFlow:
    def __init__(self,events,markers,earlier,goal,stop,body_start=0,iteration_start=0):
        self.events=events;self.markers=markers;self.earlier=earlier;self.goal=goal;self.stop=stop
        self.body_start=body_start;self.iteration_start=iteration_start;self.failures=[]
    def occurrence(self,index):return self.iteration_start+index-self.body_start
    def contains(self,r,index):return self.occurrence(r.start)<=index<self.occurrence(r.end)
    def lower_bound(self,start,floor):
        idx=floor
        while idx<len(self.markers) and self.markers[idx].offset<start:idx+=1
        return idx
    def scope_at(self,r):
        idx=self.lower_bound(r.start,r.floor)
        while idx<len(self.markers):
            m=self.markers[idx]
            if m.offset>r.start:break
            if m.offset==r.start and m.event=='primary':
                end=m.boundary if m.kind=='route' else m.end
                if end<=r.end:r.floor=idx;return idx
            idx+=1
        r.floor=idx
        return None
    def advance(self,range_,facts):
        r=replace(range_);facts=set(facts)
        if self.occurrence(r.end)<=self.earlier:return facts
        while r.start<r.end and self.occurrence(r.start)<self.stop:
            if self.occurrence(r.start)<self.earlier and not facts:
                seed=self.body_start+self.earlier-self.iteration_start
                nxt=self.lower_bound(r.start,r.floor)
                boundary=self.markers[nxt].offset if nxt<len(self.markers) and self.markers[nxt].offset<seed else seed
                if boundary>r.start:r.start=boundary
            idx=self.scope_at(r)
            if idx is not None:
                m=self.markers[idx]
                if m.kind=='route':left_end,right_end=m.end,m.boundary
                elif m.kind=='par':left_end,right_end=m.boundary,m.end
                else:left_end=right_end=m.end
                left=Range(r.start,left_end,idx+1);right=Range(left_end,right_end,idx+1)
                if m.kind=='roll':joined=self.advance(left,facts)
                elif m.kind=='route' and self.contains(left,self.earlier):joined=self.advance(left,facts)
                elif m.kind=='route' and self.contains(right,self.earlier):joined=self.advance(right,facts)
                else:
                    l=self.advance(left,facts);rr=self.advance(right,facts)
                    joined=l&rr if m.kind=='route' else l|rr
                facts=joined
                if self.occurrence(right_end)>self.stop:return facts
                r.start=right_end
            else:
                atom=self.events[r.start];occ=self.occurrence(r.start)
                if occ==self.earlier:facts.add(atom.receiver)
                else:
                    if occ>self.earlier and self.goal is not None and sender_change(self.goal,atom) and atom.sender not in facts:
                        self.failures.append({'earlier':self.earlier+self.body_start,'later':r.start,'earlier_occurrence':self.earlier,'later_occurrence':occ,'known_roles':sorted(facts)})
                    if atom.sender in facts:facts.add(atom.receiver)
                r.start+=1
        return facts

def analyze_markers(root,events):
    markers=markers_for(root);structured=[];reentry=[]
    for idx,earlier in enumerate(events):
        ends=[j+1 for j in range(idx+1,len(events)) if sender_change(earlier,events[j])]
        if earlier.sender==earlier.receiver or not ends:continue
        f=MarkerFlow(events,markers,idx,earlier,max(ends));f.advance(Range(0,len(events)),set());structured+=f.failures
    for m in markers:
        if m.kind!='roll' or m.event!='primary':continue
        for idx in range(m.offset,m.end):
            earlier=events[idx];ends=[j+1 for j in range(m.offset,m.end) if sender_change(earlier,events[j])]
            if earlier.sender==earlier.receiver or not ends:continue
            r=Range(m.offset,m.end);length=m.end-m.offset
            first=MarkerFlow(events,markers,idx-m.offset,None,float('inf'),m.offset,0)
            facts=first.advance(r,set())
            second=MarkerFlow(events,markers,idx-m.offset,earlier,length+max(ends)-m.offset,m.offset,length)
            second.advance(r,facts);reentry+=second.failures
    return structured,reentry,len(markers)
