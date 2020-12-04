# MalVerse Tests

MalVerse application to Logic Bombs. Just type *make* for a test case and watch!

## DebugMeNot

This is a very famous anti-debug trick. Check it [here](https://github.com/kirschju/debugmenot). MalVerse suggests that for its successful operation we should patch two functions:

![DebugMeNot Logic Bomb](FIGS/debugmenot1.png)

When we trace the original binary, it detects the hook and fails. However, when we execute the patched version, it successfully passes the check.

![DebugMeNot Logic Bomb](FIGS/debugmenot2.png)

## Double Ptrace

In this example, the application also tries to avoid detection via the *ptrace* check. However, it also protects itself from being subverted from a patched *ptrace* call. For such, it attempts to attach *ptrace* twice. When running in a real debugger, it is expected to fail in the first check, as *ptrace* will be already attached by the debugger. If running with a traditionally patched library, it is supposed to fail in the second check, as a succesfull call in the first check should never allow the flow to reach this second path. In a real machine, the third path is reached, thus exhibiting the malicious behavior.

![Double Ptrace Logic Bomb](FIGS/doubleptrace1.png)

Therefore, MalVerse generates a patch that is aware of the number of invocations of the *ptrace* function, returning distinct values according to them.

![Double Ptrace Logic Bomb](FIGS/doubleptrace2.png)

It allows the application to always reach the third case, regardless of any actual *ptrace* invocation.

![Double Ptrace Logic Bomb](FIGS/doubleptrace3.png)

## Clock

In this example, the application has a stalling code technique to wait some time before its execution. It aims to cause a timeout in sandbox executions. However, in addition to a logic bomb that is fired only after some time, the application protects itself from subversion from an application that does not wait such amount of time by checking the number of clock ticks spent by the function call.

![Clock Logic Bomb](FIGS/clock1.png)

In this case, MalVerse must generates a patch that return distinct values for each invocation of the clock function.

![Clock Logic Bomb](FIGS/clock2.png)

We notice that: (i) in the first case, the malicious behavior is displayed, but it takes time, which might suffice for a sandbox timeout; (ii) when the sleep function is patched to immediately return, the application detects the misbehavior and exhibits a benign behavior; and (iii) when the application is patched with our MalVerse payload, it presents the malicious behavior without waiting.

![Clock Logic Bomb](FIGS/clock3.png)

## CWD

In this example, the application only exhibits the malicious behavior when running from a given specific path.

![CWD Logic Bomb](FIGS/cwd1.png)

The patch to it requires the function to return a pointer to a variable instead to an immediate value.

![CWD Logic Bomb](FIGS/cwd2.png)

To provide a valid pointer, MalVerse generates a patch that preloads the main function to allocates the buffer and creates a global variable to the whole program context. Thus, the patched specific function might only return the address of this global  variable.

![CWD Logic Bomb](FIGS/cwd3.png)

We notice that: (i) when we run the original application, it is not malicious; but (ii) when it is patched, it displays its malicious behavior without crashing.

![CWD Logic Bomb](FIGS/cwd4.png)

## Visualizing the differences

Once one identifies the impact of distinct function returns over a binary behavior, such difference can be visualized by aligning the history of invoked functions and concretizing their values according to the distinct states.

We following observe an example of an execution flow that branches according to the distinct returns of the *strcmp* function.

![Diff Visualization](FIGS/diff1.png)

If one follows the flow a little bit, he/she notices that the right path has an additional comparison.

![Diff Visualization](FIGS/diff2.png)

In fact, both paths might present distinct function invocations after a function call return diverged.

![Diff Visualization](FIGS/diff3.png)
