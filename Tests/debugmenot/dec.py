import angr
import sys
import IPython

# Project
p = angr.Project(sys.argv[1], load_options={"auto_load_libs":False})
# CFG
cfg = p.analyses.CFGFast(normalize=True)
# Begining
state = p.factory.entry_state()
sm = p.factory.simulation_manager(state)
# Solve first check
found = sm.explore(find=lambda s: b"ptrace: PASS" in s.posix.dumps(1))
# warning user we found first
print(found.found[0].posix.dumps(1))
# we know we are looking for ptrace evasion, get it then
ptrace = found.found[0].history.simprocs.hardcopy[-4]
ptrace.set_state(found.found[0])
func = cfg.functions.get(ptrace.name)
# decompile with concrete ptrace value
d = p.analyses.Decompiler(func,concrete_values=ptrace)
# warn user we decompiled the code
print(d.codegen.text)           
# save decompiled file
open(sys.argv[1]+'.decompiler1.c','w').write(d.codegen.text)
# start from now to the end to solve the second
sm = p.factory.simulation_manager(found.found[0])
# search DFS to avoid explosion
sm.use_technique(angr.exploration_techniques.DFS())
# we found the second bypass
found = sm.explore(find=lambda s: b"ldhook: PASS" in s.posix.dumps(1))
# warn user
print(found.found[0].posix.dumps(1))
# we are looking for a comparison
memcmp = found.found[0].history.simprocs.hardcopy[-3]
memcmp.set_state(found.found[0])
func = cfg.functions.get(memcmp.name)
# decompile with concrete memcmp value
d = p.analyses.Decompiler(func,concrete_values=memcmp)
# notify user
print(d.codegen.text)
# save file
open(sys.argv[1]+'.decompiler2.c','w').write(d.codegen.text)
