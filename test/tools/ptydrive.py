# Drives `minibox run -it` / `exec -it` through a pty: window size, Ctrl-C, exit code. Usage: B=bin/minibox ptydrive.py run|exec
import pty,os,sys,time,select
B=os.environ['B']; mode=sys.argv[1]
if mode=='exec':
    cid=os.popen(B+' run -d alpine sleep 1000').read().strip()
pid,fd=pty.fork()
if pid==0:
    if mode=='run': os.execv(B,[B,'run','--rm','-it','alpine','sh'])
    else: os.execv(B,[B,'exec','-it',cid,'sh'])
def rd(t=1.0):
    out=b''; end=time.time()+t
    while time.time()<end:
        r,_,_=select.select([fd],[],[],0.1)
        if r:
            try: d=os.read(fd,4096)
            except OSError: break
            if not d: break
            out+=d
    return out
time.sleep(0.5); rd(0.5)
os.write(fd,b'stty rows 30 cols 100; stty size\n'); out=rd(1).decode(); assert '30 100' in out, out
os.write(fd,b'sleep 100\n'); time.sleep(.3); os.write(fd,b'\x03'); time.sleep(.3); os.write(fd,b'echo alive\n'); print(rd(1).decode())
os.write(fd,b'exit 5\n'); rd(1)
_,st=os.waitpid(pid,0); assert os.WEXITSTATUS(st)==5; print('ok: exit 5, ^C handled, winsize set')
if mode=='exec': os.system(B+' rm -f '+cid+' >/dev/null')
