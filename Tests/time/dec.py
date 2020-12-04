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
func = cfg.functions.get('mal')
found = sm.explore(find=func.addr)
# get first decision point
decision_func = found.found[0].history.simprocs.hardcopy[0]
# Update state for the current one
decision_func.set_state(found.found[0])
# get handler to this func in the original cfg
cfg_func = cfg.functions.get(decision_func.name)
# Original decompilation
dec = p.analyses.Decompiler(cfg_func) 
open(sys.argv[1]+'.decompiler1.c','w').write(dec.codegen.text)
# Concretized decompilation
dec = p.analyses.Decompiler(cfg_func,concrete_values=decision_func)
open(sys.argv[1]+'.decompiler2.c','w').write(dec.codegen.text)       
