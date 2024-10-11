# makefile
CC=cl
LINK=link
CDEBUG=/D "NDEBUG"
CFLAGS= /c /GS- /Oi /MT /Gy
CVARS=
LDFLAGS=/NODEFAULTLIB /SUBSYSTEM:WINDOWS /ENTRY:WinMain /ORDER:@spawncalc\order.txt
LDEBUG=

all: spawncalc.exe

clean:
	if exist main.obj del main.obj
	if exist spawncalc.exe del spawncalc.exe

spawncalc.exe: main.obj
	$(LINK) $(LDEBUG) $(LDFLAGS) -out:spawncalc.exe main.obj

main.obj:
	$(CC) $(CDEBUG) $(CFLAGS) $(CVARS) /Fomain.obj spawncalc\main.c
