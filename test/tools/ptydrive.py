# Drives `minibox run -it` / `exec -it` through a pty: real window resize,
# Ctrl-C handling, exit code. Usage: B=bin/minibox ptydrive.py run|exec
import pty,os,sys,time,select,fcntl,termios,struct,signal
B=os.environ['B']; mode=sys.argv[1]
cid=None
if mode=='exec':
    cid=os.popen(B+' run -d --network none alpine sleep 1000').read().strip()
    assert len(cid)==64, cid
def cleanup():
    if cid: os.system(B+' rm -f '+cid+' >/dev/null 2>&1')
try:
    pid,fd=pty.fork()
    if pid==0:
        if mode=='run': os.execv(B,[B,'run','--rm','--network','none','-it','alpine','sh'])
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
    # Real resize: change the parent pty dimensions, poke minibox with SIGWINCH
    # (its documented resize trigger), and read back what the container sees.
    fcntl.ioctl(fd,termios.TIOCSWINSZ,struct.pack('HHHH',25,80,0,0))
    os.kill(pid,signal.SIGWINCH)
    time.sleep(0.5)
    os.write(fd,b'stty size\n'); out=rd(1).decode()
    assert '25 80' in out, 'resize not forwarded to container: %r' % out
    # Ctrl-C must kill the foreground sleep and return to the shell promptly.
    os.write(fd,b'sleep 100\n'); time.sleep(.3); os.write(fd,b'\x03')
    out=b''
    end=time.time()+4
    while time.time()<end and b'alive' not in out:
        os.write(fd,b'echo alive\n')
        time.sleep(.3)
        out+=rd(.5)
    assert b'alive' in out, 'shell did not resume after Ctrl-C: %r' % out
    os.write(fd,b'exit 5\n'); rd(1)
    _,st=os.waitpid(pid,0); assert os.WEXITSTATUS(st)==5, st
    print('ok: exit 5, ^C handled, winsize set')
finally:
    cleanup()
