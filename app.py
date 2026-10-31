import os, sqlite3, hashlib, hmac, secrets, time, json, re
from pathlib import Path
from contextlib import contextmanager
from datetime import datetime
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parent
DB = Path(os.getenv('DB_PATH', ROOT / 'data' / 'events.sqlite3'))
DB.parent.mkdir(parents=True, exist_ok=True)
ADMIN_USER = os.getenv('ADMIN_USER', 'admin')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', '')
SECRET = os.getenv('SESSION_SECRET', '')
if len(ADMIN_PASSWORD) < 12 or len(SECRET) < 32:
    raise RuntimeError('Set ADMIN_PASSWORD (12+ chars) and SESSION_SECRET (32+ chars) before starting')
SECURE_COOKIE = os.getenv('COOKIE_SECURE', '1') == '1'

app = FastAPI(title='Elite Events OS', docs_url=None, redoc_url=None, openapi_url=None)
app.mount('/static', StaticFiles(directory=ROOT / 'static'), name='static')

def conn():
    db=sqlite3.connect(DB, timeout=10)
    db.row_factory=sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    db.execute('PRAGMA journal_mode=WAL')
    return db

def init():
    with conn() as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, title TEXT NOT NULL, city TEXT DEFAULT '', location TEXT DEFAULT '', event_date TEXT DEFAULT '', product TEXT DEFAULT '', goal TEXT DEFAULT '', budget REAL DEFAULT 0, status TEXT DEFAULT 'planning', created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS doctors (id INTEGER PRIMARY KEY, name TEXT NOT NULL, specialty TEXT DEFAULT '', clinic TEXT DEFAULT '', city TEXT DEFAULT '', phone TEXT DEFAULT '', rep TEXT DEFAULT '', email TEXT DEFAULT '', notes TEXT DEFAULT '', created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS tasks (id INTEGER PRIMARY KEY, title TEXT NOT NULL, event_id INTEGER REFERENCES events(id) ON DELETE SET NULL, owner TEXT DEFAULT '', due_date TEXT DEFAULT '', status TEXT DEFAULT 'todo', priority TEXT DEFAULT 'normal', phase TEXT DEFAULT 'before', notes TEXT DEFAULT '', created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS vendors (id INTEGER PRIMARY KEY, name TEXT NOT NULL, category TEXT DEFAULT '', event_id INTEGER REFERENCES events(id) ON DELETE SET NULL, contact TEXT DEFAULT '', cost REAL DEFAULT 0, status TEXT DEFAULT 'quoted', notes TEXT DEFAULT '', created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS agenda (id INTEGER PRIMARY KEY, title TEXT NOT NULL, event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE, starts_at TEXT DEFAULT '', ends_at TEXT DEFAULT '', speaker TEXT DEFAULT '', owner TEXT DEFAULT '', notes TEXT DEFAULT '', created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS invitations (id INTEGER PRIMARY KEY, event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE, doctor_id INTEGER NOT NULL REFERENCES doctors(id) ON DELETE CASCADE, status TEXT DEFAULT 'pending', notes TEXT DEFAULT '', created_at TEXT DEFAULT CURRENT_TIMESTAMP, UNIQUE(event_id,doctor_id));
        CREATE INDEX IF NOT EXISTS idx_tasks_event ON tasks(event_id);
        CREATE INDEX IF NOT EXISTS idx_inv_event ON invitations(event_id);
        ''')
init()

SCHEMAS={
 'events': {'title':'text','city':'text','location':'text','event_date':'text','product':'text','goal':'text','budget':'number','status':'text'},
 'doctors': {'name':'text','specialty':'text','clinic':'text','city':'text','phone':'text','rep':'text','email':'text','notes':'text'},
 'tasks': {'title':'text','event_id':'fk','owner':'text','due_date':'text','status':'text','priority':'text','phase':'text','notes':'text'},
 'vendors': {'name':'text','category':'text','event_id':'fk','contact':'text','cost':'number','status':'text','notes':'text'},
 'agenda': {'title':'text','event_id':'fk','starts_at':'text','ends_at':'text','speaker':'text','owner':'text','notes':'text'},
 'invitations': {'event_id':'fk','doctor_id':'fk','status':'text','notes':'text'}
}
REQUIRED={'events':['title'],'doctors':['name'],'tasks':['title'],'vendors':['name'],'agenda':['title','event_id'],'invitations':['event_id','doctor_id']}

def session_value(user,expires):
    payload=f'{user}:{expires}'
    sig=hmac.new(SECRET.encode(),payload.encode(),hashlib.sha256).hexdigest()
    return f'{payload}:{sig}'

def authenticated(request):
    val=request.cookies.get('elite_session','')
    try:
        user,expires,sig=val.rsplit(':',2)
        if user!=ADMIN_USER or int(expires)<time.time(): return False
        expected=session_value(user,expires).rsplit(':',1)[1]
        return hmac.compare_digest(expected,sig)
    except (ValueError,TypeError): return False

@app.middleware('http')
async def security(request:Request,call_next):
    if request.url.path.startswith('/api/') and request.url.path not in ('/api/login','/api/auth'):
        if not authenticated(request): return Response(json.dumps({'detail':'Unauthorized'}),status_code=401,media_type='application/json')
        if request.method in ('POST','PUT','PATCH','DELETE'):
            if request.headers.get('x-elite-request')!='app': return Response('Forbidden',status_code=403)
    res=await call_next(request)
    res.headers['X-Content-Type-Options']='nosniff'
    res.headers['X-Frame-Options']='DENY'
    res.headers['Referrer-Policy']='strict-origin-when-cross-origin'
    res.headers['Content-Security-Policy']="default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; base-uri 'self'; object-src 'none'"
    return res

class Login(BaseModel):
    username:str
    password:str

@app.get('/')
def home():return FileResponse(ROOT/'static'/'index.html')

@app.get('/api/auth')
def auth(request:Request):return {'authenticated':authenticated(request)}

@app.post('/api/login')
def login(body:Login,response:Response):
    # constant time comparison (no user enumeration)
    valid_u=hmac.compare_digest(body.username.encode(),ADMIN_USER.encode())
    valid_p=hmac.compare_digest(body.password.encode(),ADMIN_PASSWORD.encode())
    if not (valid_u and valid_p): raise HTTPException(401,'بيانات الدخول غير صحيحة')
    expires=str(int(time.time()+60*60*12))
    response.set_cookie('elite_session',session_value(ADMIN_USER,expires),httponly=True,secure=SECURE_COOKIE,samesite='strict',max_age=43200,path='/')
    return {'ok':True}

@app.post('/api/logout')
def logout(response:Response):
    response.delete_cookie('elite_session',path='/')
    return {'ok':True}

def validate(resource,data,partial=False):
    if resource not in SCHEMAS:raise HTTPException(404,'Unknown resource')
    allowed=SCHEMAS[resource]
    if not isinstance(data,dict):raise HTTPException(400,'Invalid JSON object')
    unknown=set(data)-set(allowed)
    if unknown:raise HTTPException(400,'Unsupported field')
    if not partial:
        for k in REQUIRED[resource]:
            if not data.get(k):raise HTTPException(400,f'{k} is required')
    out={}
    for key,v in data.items():
        kind=allowed[key]
        if kind in ('fk','number'):
            if v in ('',None):out[key]=None if kind=='fk' else 0
            else:
                try:out[key]=int(v) if kind=='fk' else float(v)
                except (TypeError,ValueError):raise HTTPException(400,f'Invalid number: {key}')
        else:
            if not isinstance(v,str):raise HTTPException(400,f'Invalid string: {key}')
            if len(v)>2000:raise HTTPException(400,'Field too long')
            out[key]=v.strip()
    return out

@app.get('/api/{resource}')
def list_items(resource:str,event_id:int|None=None,q:str=''):
    if resource not in SCHEMAS:raise HTTPException(404)
    sql=f'SELECT * FROM {resource}'
    args=[];cond=[]
    if event_id is not None and 'event_id' in SCHEMAS[resource]:cond.append('event_id=?');args.append(event_id)
    if q:
        searchcol={'events':'title','doctors':'name','tasks':'title','vendors':'name','agenda':'title'}.get(resource)
        if searchcol:cond.append(f'{searchcol} LIKE ?');args.append('%'+q[:100]+'%')
    if cond:sql+=' WHERE '+' AND '.join(cond)
    sql+=' ORDER BY id DESC LIMIT 1000'
    with conn() as db:return [dict(r) for r in db.execute(sql,args).fetchall()]

@app.post('/api/{resource}')
async def create_item(resource:str,request:Request):
    data=validate(resource,await request.json())
    cols=','.join(data);placeholders=','.join('?' for _ in data)
    try:
        with conn() as db:
            cur=db.execute(f'INSERT INTO {resource} ({cols}) VALUES ({placeholders})',list(data.values()))
            return dict(db.execute(f'SELECT * FROM {resource} WHERE id=?',(cur.lastrowid,)).fetchone())
    except sqlite3.IntegrityError as e:raise HTTPException(409,'Duplicate entry or invalid reference') from e

@app.patch('/api/{resource}/{item_id}')
async def update_item(resource:str,item_id:int,request:Request):
    data=validate(resource,await request.json(),True)
    if not data:raise HTTPException(400,'No updates')
    sql=', '.join(f'{k}=?' for k in data)
    try:
        with conn() as db:
            cur=db.execute(f'UPDATE {resource} SET {sql} WHERE id=?',list(data.values())+[item_id])
            if not cur.rowcount:raise HTTPException(404,'Not found')
            return dict(db.execute(f'SELECT * FROM {resource} WHERE id=?',(item_id,)).fetchone())
    except sqlite3.IntegrityError as e:raise HTTPException(409,'Invalid reference') from e

@app.delete('/api/{resource}/{item_id}')
def delete_item(resource:str,item_id:int):
    if resource not in SCHEMAS:raise HTTPException(404)
    with conn() as db:
        cur=db.execute(f'DELETE FROM {resource} WHERE id=?',(item_id,))
        if not cur.rowcount:raise HTTPException(404,'Not found')
        return {'ok':True}
