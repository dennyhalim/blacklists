#!/usr/bin/env python3
from __future__ import annotations
import hashlib, html, ipaddress, json, re, urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

DIST=Path('dist'); README=Path('README.md'); INDEX=Path('index.html')
START='<!-- DOMAIN_BLOCKLISTS_START -->'; END='<!-- DOMAIN_BLOCKLISTS_END -->'
INDEX_START='<!-- DOMAIN_BLOCKLISTS_START -->'; INDEX_END='<!-- DOMAIN_BLOCKLISTS_END -->'

SOURCES={
 'scam1':'https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/rpz/spam-tlds-rpz.txt',
 'phish1':'https://phishing.army/download/phishing_army_blocklist_extended.txt',
 'phish2':'https://malware-filter.gitlab.io/malware-filter/phishing-filter.txt',
 'phish3':'https://raw.githubusercontent.com/phishdestroy/destroylist/main/rootlist/online_root_domains.txt',
 #'phishunt':'https://phishunt.io/feed.txt',
 #'fake1':'https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/fake-onlydomains.txt',
 #'tif':'https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif-onlydomains.txt',
 'tifmini':'https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif.mini-onlydomains.txt',
 'urlhaus':'https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-online.txt',
 'cti':'https://raw.githubusercontent.com/DNSBunker/CTI/main/domains.txt',
 'gambling1':'https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/gambling.mini-onlydomains.txt',
 'gambling2':'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling-only/hosts',
 'nsfw1':'https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/nsfw-onlydomains.txt',
 'nsfw2':'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts',
 #'nsfw3':'https://nsfw.oisd.nl/domainswild2',
 'nsfw3':'https://nsfw-small.oisd.nl/domainswild2',
}
ALLOWLIST=('wordpress.com','hashnode.dev','com.cdn.cloudflare.net','weebly.com','edgeone.dev','edgeone.app',
              'squarespace.com','surge.sh',)
#do NOT use same name with ip blocklist, it will get replaced
LISTS={
 'threat': {'from':('tifmini','cti','urlhaus',), 'merge_subdomains':3},
 'phishing': {'from':('phish1','phish2','phish3','scam1',), 'merge_subdomains':3},
 'gambling': {'from':('gambling1','gambling2',), 'merge_subdomains':3},
 'nsfw': {'from':('nsfw1','nsfw2','nsfw3',), 'merge_subdomains':3},
 #'security': {'from':('threat','fake',), 'remove_labels':('www','web'),'merge_subdomains':3},
 #'all': {'from':('threat','fake','gambling','nsfw',), 'remove_labels':('www','web'), 'merge_subdomains':3},
}

EXPORTS=('plain','hosts','adblock','dnsmasq','rpz','wildcard')
PLATFORMS={'Pi-hole':'plain','AdGuard Home':'adblock','uBlock Origin':'adblock','Adblock Plus':'adblock','dnsmasq':'dnsmasq','BIND RPZ':'rpz'}
PSL_URL='https://publicsuffix.org/list/public_suffix_list.dat'
TRANSFORM_LOG=DIST/'transform.log'
ACTIVE_PSL=None
DOMAIN_RE=re.compile(r'^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$',re.I)
ABP_RE=re.compile(r'^(?P<exc>@@)?\|\|(?P<domain>[a-z0-9._-]+)\^(?P<opts>\$.*)?$',re.I)

def write(p,s): p.parent.mkdir(parents=True,exist_ok=True); p.write_text(s,encoding='utf-8',newline='\n')
def norm(v):
 v=v.strip().rstrip('.').lower(); v=v[2:] if v.startswith('*.') else v
 if not v or '.' not in v:return None
 try:v=v.encode('idna').decode('ascii')
 except UnicodeError:return None
 if not DOMAIN_RE.fullmatch(v):return None
 try:ipaddress.ip_address(v); return None
 except ValueError:return v

def parse(text):
 domains,native=set(),set()
 for raw in text.splitlines():
  line=raw.strip()
  if not line or line.startswith(('#','!')):continue
  clean=line.split('#',1)[0].strip(); f=clean.split()
  if len(f)>=2:
   try:ipaddress.ip_address(f[0])
   except ValueError:pass
   else:
    found=False
    for x in f[1:]:
     d=norm(x)
     if d:domains.add(d); found=True
    if found:native.add(clean)
    continue
  m=ABP_RE.fullmatch(line)
  if m:
   d=norm(m.group('domain'))
   if d:
    if not m.group('exc') and not m.group('opts'):domains.add(d)
    native.add(line)
   continue
  d=norm(line)
  if d:domains.add(d)
  else:native.add(line)  # preserve potentially meaningful browser/adblock/IP rules
 return domains,native

def same_or_sub(d,p):return d==p or d.endswith('.'+p)
def allowset(values):
 out=set()
 for x in values:
  d=norm(x)
  if not d:raise ValueError(f'invalid allowlist domain: {x!r}')
  out.add(d)
 return out

def protected(d,allow):return any(same_or_sub(d,a) for a in allow)
def remove_labels(domains,labels,allow,list_name,events):
 labels={x.lower() for x in labels}; out=set()
 for original in domains:
  d=original
  if protected(d,allow):out.add(d); continue
  while '.' in d:
   first,rest=d.split('.',1)
   if first not in labels or protected(rest,allow):break
   d=rest
  out.add(d)
  if d!=original:events.append((list_name,'remove_label',original,d))
 return out

def parse_psl(text):
 exact,wild,exc=set(),set(),set()
 for raw in text.splitlines():
  line=raw.strip()
  if not line or line.startswith('//'):continue
  target=exc if line.startswith('!') else wild if line.startswith('*.') else exact
  line=line[1:] if line.startswith('!') else line[2:] if line.startswith('*.') else line
  try:line=line.lower().encode('idna').decode('ascii')
  except UnicodeError:continue
  target.add(line)
 return exact,wild,exc

def suffix(d):
 if ACTIVE_PSL is None:raise RuntimeError('PSL not loaded')
 exact,wild,exc=ACTIVE_PSL; labels=d.split('.'); best=1
 for i in range(len(labels)):
  c='.'.join(labels[i:])
  if c in exc:return '.'.join(labels[i+1:])
  if c in exact:best=max(best,len(labels)-i)
  if i>0 and c in wild:best=max(best,len(labels)-i+1)
 return '.'.join(labels[-best:])

def floor(d):
 s=suffix(d); a=d.split('.'); b=s.split('.')
 return None if len(a)<=len(b) else '.'.join(a[-len(b)-1:])
def parent(d):
 if '.' not in d:return None
 p=d.split('.',1)[1]; f=floor(d)
 return p if f and len(p.split('.'))>=len(f.split('.')) else None

def merge(domains,n,allow,list_name,events):
 if n<2:raise ValueError('merge_subdomains must be >= 2')
 out=set(domains)
 while True:
  groups=defaultdict(set)
  for d in out:
   p=parent(d)
   if p:groups[p].add(d)
  candidates=[(p.count('.'),p,kids) for p,kids in groups.items() if len(kids)>=n and not any(same_or_sub(a,p) for a in allow)]
  if not candidates:break
  changed=False
  for _,p,kids in sorted(candidates,reverse=True):
   live=kids & out
   if len(live)>=n and not any(same_or_sub(a,p) for a in allow):
    for child in sorted(live):events.append((list_name,'merge_domain',child,p))
    out-=live; out.add(p); changed=True
  if not changed:break
 return out

def download(name,url):
 print('download:',name,url); req=urllib.request.Request(url,headers={'User-Agent':'domain-blocklist-builder/1.0'})
 with urllib.request.urlopen(req,timeout=120) as r:return r.read().decode('utf-8','replace')

def resolve(name,sources,cache,events,stack=()):
 if name in cache:return cache[name]
 if name in stack:raise ValueError('LISTS cycle: '+' -> '.join((*stack,name)))
 cfg=LISTS[name]; domains,native=set(),set()
 for ref in cfg['from']:
  if ref in sources:d,n=sources[ref]
  elif ref in LISTS:d,n=resolve(ref,sources,cache,events,(*stack,name))
  else:raise ValueError(f'{name}: unknown source/list {ref!r}')
  domains|=set(d); native|=set(n)
 allow=allowset(ALLOWLIST)|allowset(cfg.get('allowlist',()))
 if cfg.get('remove_labels'):domains=remove_labels(domains,cfg['remove_labels'],allow,name,events)
 if cfg.get('merge_subdomains') is not None:domains=merge(domains,int(cfg['merge_subdomains']),allow,name,events)
 cache[name]=(frozenset(domains),frozenset(native)); return cache[name]

def domain_sort_key(d):
 root=floor(d) or d; labels=d.split('.')
 return (root,len(labels),tuple(reversed(labels)))
def export(name,domains,native):
 domains=sorted(domains,key=domain_sort_key); files={}
 data={
  'plain':'\n'.join(domains)+'\n',
  'hosts':''.join(f'0.0.0.0 {d}\n' for d in domains),
  'adblock':'\n'.join(sorted(set(native)|{f'||{d}^' for d in domains}))+'\n',
  'dnsmasq':''.join(f'address=/{d}/#\n' for d in domains),
  'rpz':''.join(f'{d} CNAME .\n' for d in domains),
  'wildcard':''.join(f'*.{d}\n' for d in domains),
 }
 ext={'plain':'txt','hosts':'txt','adblock':'txt','dnsmasq':'conf','rpz':'rpz','wildcard':'txt'}
 for fmt in EXPORTS:
  p=DIST/fmt/f'{name}.{ext[fmt]}'; write(p,data[fmt]); files[fmt]=p.as_posix()
 return files

def sha(p):
 h=hashlib.sha256(); h.update(p.read_bytes()); return h.hexdigest()

def transform_log(events):
 counts=defaultdict(lambda:{'remove_label':0,'merge_domain':0})
 for name,op,src,dst in events:counts[name][op]+=1
 lines=[f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",'', 'SUMMARY']
 tr=tm=0
 for name in LISTS:
  r=counts[name]['remove_label']; m=counts[name]['merge_domain']; tr+=r; tm+=m
  lines.append(f'{name}: labels_removed={r} domains_merged={m}')
 lines += [f'TOTAL: labels_removed={tr} domains_merged={tm}','','DETAILS']
 for name,op,src,dst in sorted(events):lines.append(f'{name}\t{op}\t{src}\t->\t{dst}')
 write(TRANSFORM_LOG,'\n'.join(lines)+'\n')

def metadata(m):
 manifest_path=DIST/'manifest.json'
 manifest={}
 if manifest_path.exists():
  try:
   loaded=json.loads(manifest_path.read_text(encoding='utf-8'))
   if isinstance(loaded,dict):manifest=loaded
  except (OSError,json.JSONDecodeError) as e:
   raise RuntimeError(f'cannot read existing manifest: {e}') from e

 # Preserve metadata owned by other builders and replace only our section.
 manifest['domain']=m
 write(manifest_path,json.dumps(manifest,indent=2,sort_keys=True)+'\n')

 # Rebuild checksums from all current dist files so entries from other
 # builders are preserved and stale checksum lines disappear.
 files=sorted(p for p in DIST.rglob('*') if p.is_file() and p.name!='SHA256SUMS')
 write(DIST/'SHA256SUMS',''.join(f'{sha(p)}  {p.as_posix()}\n' for p in files))
def mdlink(label,p):return f'[{label}]({p})'
def section(m):
 lines=[START,f"Last updated: **{m['generated_at']}**",'', '| List | Domains | Native rules | Plain | Hosts | Adblock | dnsmasq | RPZ | Wildcard |','|---|---:|---:|---|---|---|---|---|---|']
 for name,x in m['lists'].items():
  cells=[mdlink(f,x['files'][f]) for f in EXPORTS]
  lines.append(f"| `{name}` | {x['domains']:,} | {x['native_rules']:,} | "+' | '.join(cells)+' |')
 lines+=['','### Platform compatibility','']+[f'- **{p}** → `{fmt}` output' for p,fmt in PLATFORMS.items()]+[END]
 return '\n'.join(lines)
def docs(m):
 s=section(m)
 if README.exists():
  t=README.read_text(encoding='utf-8'); a,b=START in t,END in t
  if a!=b:raise RuntimeError('README markers malformed')
  if a:before,rest=t.split(START,1); _,after=rest.split(END,1); t=before+s+after
  else:t=t.rstrip()+'\n\n## Generated Domain Lists\n\n'+s+'\n'
 else:t='# Domain Blocklists\n\n'+s+'\n'
 write(README,t)
 rows=[]
 for name,x in m['lists'].items():
  links=' · '.join(f'<a href="/{html.escape(p)}">{html.escape(f)}</a>' for f,p in x['files'].items())
  rows.append(f"<tr><td>{html.escape(name)}</td><td>{x['domains']:,}</td><td>{x['native_rules']:,}</td><td>{links}</td></tr>")
 plats=''.join(f'<tr><td>{html.escape(p)}</td><td>{html.escape(f)}</td></tr>' for p,f in PLATFORMS.items())
 section_html=f'''{INDEX_START}<section id="domain-blocklists"><h2>Domain Blocklists</h2><p>Last updated: {m['generated_at']}</p><table><tr><th>List</th><th>Domains</th><th>Native rules</th><th>Formats</th></tr>{''.join(rows)}</table><h3>Platform compatibility</h3><table>{plats}</table></section>{INDEX_END}'''
 if INDEX.exists():
  page=INDEX.read_text(encoding='utf-8'); a,b=INDEX_START in page,INDEX_END in page
  if a!=b:raise RuntimeError('index.html domain markers malformed')
  if a:before,rest=page.split(INDEX_START,1); _,after=rest.split(INDEX_END,1); page=before+section_html+after
  else:
   pos=page.lower().rfind('</body>')
   page=(page[:pos].rstrip()+'\n'+section_html+'\n'+page[pos:]) if pos>=0 else page.rstrip()+'\n'+section_html+'\n'
 else:
  page=f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Blocklists</title><style>body{{max-width:1100px;margin:40px auto;padding:0 20px;font:16px/1.5 system-ui,sans-serif;background:#17191c;color:#e6e7e9}}a{{color:#9fc3e8}}table{{width:100%;border-collapse:collapse;margin:1rem 0 2rem}}th,td{{text-align:left;padding:.55rem .7rem;border-bottom:1px solid #3a3d42}}</style></head><body><h1>Blocklists</h1>{section_html}</body></html>'''
 write(INDEX,page)
def main():
 global ACTIVE_PSL
 if set(SOURCES)&set(LISTS):raise ValueError('SOURCES and LISTS names overlap')
 ACTIVE_PSL=parse_psl(download('public-suffix-list',PSL_URL))
 if not ACTIVE_PSL[0]:raise RuntimeError('Public Suffix List contains no usable rules')
 required=set()
 def collect(n,stack=()):
  if n in SOURCES:required.add(n); return
  if n not in LISTS:raise ValueError(f'unknown source/list: {n}')
  if n in stack:raise ValueError('LISTS cycle: '+' -> '.join((*stack,n)))
  for r in LISTS[n].get('from',()):collect(r,(*stack,n))
 for n in LISTS:collect(n)
 parsed={n:parse(download(n,SOURCES[n])) for n in sorted(required)}; cache={}; events=[]
 m={'generated_at':datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),'sources':{n:SOURCES[n] for n in sorted(required)},'platforms':PLATFORMS,'lists':{}}
 for n in LISTS:
  d,r=resolve(n,parsed,cache,events); files=export(n,d,r); m['lists'][n]={'domains':len(d),'native_rules':len(r),'files':files,'config':LISTS[n]}; print('built:',n,len(d),'domains',len(r),'native rules')
 transform_log(events); metadata(m); docs(m)
if __name__=='__main__':main()
