from __future__ import annotations

from collections import Counter

from models import Endpoint, Finding, SEVERITY_ORDER

WEIGHTS={"Critical":10,"High":7,"Medium":4,"Low":1,"Info":0}

def posture_score(findings:list[Finding],endpoint_count:int)->int:
    if endpoint_count<=0: return 100
    penalty=sum(WEIGHTS[f.severity] for f in findings)
    maximum=endpoint_count*20
    return max(0,round(100*(1-min(penalty,maximum)/maximum)))

def prioritized_findings(findings:list[Finding],endpoints:list[Endpoint])->list[Finding]:
    context={(e.method,e.path):e for e in endpoints}
    def key(f:Finding):
        method,path=f.endpoint.split(" ",1)
        e=context[(method,path)]
        criticality={"low":0,"medium":1,"high":2,"critical":3}[e.business_criticality]
        return (SEVERITY_ORDER[f.severity],1 if e.internet_exposed else 0,criticality)
    return sorted(findings,key=key,reverse=True)

def summarize(findings:list[Finding],endpoint_count:int)->dict:
    counts=Counter(f.severity for f in findings)
    return {"endpoints_assessed":endpoint_count,"findings":len(findings),"critical":counts["Critical"],"high":counts["High"],"medium":counts["Medium"],"low":counts["Low"],"posture_score":posture_score(findings,endpoint_count)}
