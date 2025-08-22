# Fugue

I read Prelude's whitepaper and thought it would be fun to reimplement parts of it.
Particularly the memory tracker stuff.

Sadly my laptop is ancient and Intel PT isn't supported. Maybe in the future I'll come back and add that.

So currently I've got the LBR event being emitted when sampling the Timer counter at 121.1 microseconds. Also emitting LBR events on context switch events.

I'm sure there are plenty of problems with my implementation, but it was a fun vacation project.


## Sources
- https://info.preludesecurity.com/hubfs/Content/Closing%20the%20Execution%20Gap.pdf
- https://gist.github.com/mmozeiko/bd5923bcd9d20b5b9946691932ec95fa
- https://www.computerenhance.com/p/real-time-pmcs-on-windows-with-etw
- https://github.com/microsoft/perfview/blob/main/src/TraceEvent/TraceEventSession.cs
- Intel SDM vol 3
- https://github.com/ionescu007/winipt
- probably a handful I've forgotten

## Building / Usage

```
cl /O2 fugue.c
# fugue.exe <num seconds to run for>
fugue.exe 120
```
