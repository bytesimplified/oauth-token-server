from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse
from .config import settings

router = APIRouter()


@router.get("/admin/ui", response_class=HTMLResponse, include_in_schema=False)
def admin_dashboard():
    if not settings.admin_ui_enabled:
        raise HTTPException(404, "Dashboard disabled")
    return r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>OAuth Admin</title>
<style>
body{font:15px system-ui,sans-serif;max-width:1000px;margin:2rem auto;padding:0 1rem;color:#182638}
h1{margin-bottom:.2rem}button,input,textarea{padding:.6rem;margin:.25rem;border:1px solid #abb6c4;border-radius:5px}
button{cursor:pointer;background:#173d66;color:white}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#edf2f7;padding:1rem}
table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #ddd;text-align:left;padding:.5rem}
</style></head><body>
<h1>OAuth administration</h1><p>Local development UI. Use HTTPS and network access restrictions in production.</p>
<label>Admin API key <input type="password" id="key" autocomplete="off" placeholder="Enter API key"></label>
<button onclick="load()">Refresh</button>
<h2>Overview</h2><pre id="stats">Not loaded</pre>
<h2>Clients</h2><div id="clients"></div>
<h3>Create client</h3>
<label>Allowed scopes <input id="scopes" value="orders:read orders:write"></label>
<label>Default scopes <input id="defaults" value="orders:read"></label>
<button onclick="createClient()">Create client</button>
<h2>Audit events</h2><pre id="audit"></pre>
<h2>Result (new secrets shown once)</h2><pre id="result"></pre>
<script>
const key=()=>document.getElementById('key').value;
async function api(path,method='GET',body){
  const response=await fetch('/admin/'+path,{method,headers:{'X-Admin-Key':key(),'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined,cache:'no-store'});
  const result=await response.json();if(!response.ok)throw Error(JSON.stringify(result));return result;
}
const out=s=>document.getElementById('result').textContent=JSON.stringify(s,null,2);
async function load(){
 try{
  document.getElementById('stats').textContent=JSON.stringify(await api('stats'),null,2);
  const clients=await api('clients'), table=document.createElement('table');
  const header=document.createElement('tr');
  for(const name of ['Client ID','Scopes','Active','Actions']){const th=document.createElement('th');th.textContent=name;header.appendChild(th)}table.appendChild(header);
  for(const c of clients){
    const tr=document.createElement('tr');
    for(const val of [c.client_id,c.scopes.join(' '),String(c.active)]){const td=document.createElement('td');td.textContent=val;tr.appendChild(td)}
    const td=document.createElement('td');
    for(const [label,path] of [['Rotate secret','rotate-secret'],['Deactivate','deactivate']]){
      const button=document.createElement('button');button.textContent=label;
      button.onclick=async()=>{if(!confirm(label+' for '+c.client_id+'?'))return;try{out(await api('clients/'+encodeURIComponent(c.client_id)+'/'+path,'POST'));await load()}catch(e){out({error:e.message})}};
      td.appendChild(button)
    }tr.appendChild(td);table.appendChild(tr)
  }
  document.getElementById('clients').replaceChildren(table);
  document.getElementById('audit').textContent=JSON.stringify(await api('audit?limit=30'),null,2);
 }catch(e){out({error:e.message})}
}
async function createClient(){
 try{out(await api('clients','POST',{scopes:document.getElementById('scopes').value.split(/\s+/).filter(Boolean),default_scopes:document.getElementById('defaults').value.split(/\s+/).filter(Boolean)}));await load()}catch(e){out({error:e.message})}
}
</script></body></html>"""
