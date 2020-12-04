import angr
import sys
import IPython

# Project
p = angr.Project(sys.argv[1], load_options={"auto_load_libs":False})
# Normalized for decompilation
cfg = p.analyses.CFGFast(normalize=True)
# From begining
state = p.factory.entry_state()
sm = p.factory.simulation_manager(state)
# Until find a print
func = cfg.functions.get('ok')
found = sm.explore(find=func.addr,num_find=2)
# get first decision point
decision_func1 = found.found[1].history.simprocs.hardcopy[0]
decision_func2 = found.found[1].history.simprocs.hardcopy[1]
# Update state for the current one
decision_func1.set_state(found.found[1])
decision_func2.set_state(found.found[1])
# get handler to this func in the original cfg
cfg_func = cfg.functions.get(decision_func1.name)
# Original decompilation
dec = p.analyses.Decompiler(cfg_func) 
open(sys.argv[1]+'.decompiler1.c','w').write(dec.codegen.text)
# Concretized decompilation
dec = p.analyses.Decompiler(cfg_func,concrete_values=[decision_func1,decision_func2])
open(sys.argv[1]+'.decompiler2.c','w').write(dec.codegen.text)       
print(dec.codegen.text)       
#IPython.embed()
