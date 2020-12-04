import angr
import sys
import IPython

class SimInvocationsCompare(angr.Analysis):
    def __init__(self, state1, state2):
        if type(state1) is not angr.sim_state.SimState:
            raise ValueError("State1 is not a valid SimState")
        if type(state2) is not angr.sim_state.SimState:
            raise ValueError("State1 is not a valid SimState")
        if state1 == state2:
            raise ValueError("State1 and State2 are the same!")
        func_s1 = state1.history.simprocs.hardcopy
        func_s2 = state2.history.simprocs.hardcopy
        idx1=0
        idx2=0
        last_idx2 = idx2
        while(idx1 < len(func_s1)):
            while(idx2<len(func_s2) and func_s1[idx1]!=func_s2[idx2]):
                idx2+=1
            if idx2>=len(func_s2):
                print("{:<50}\t<-\t".format(func_s1[idx1].pp_str(state=state1,concretize=True)))
                idx2=last_idx2
            else:
                while(last_idx2<idx2):
                    print("{:<50}\t->\t{:<50}".format("",func_s2[last_idx2].pp_str(state=state2,concretize=True)))
                    last_idx2+=1
                s1 = func_s1[idx1].pp_str(state=state1,concretize=True)
                s2 = func_s2[idx2].pp_str(state=state2,concretize=True)
                if s1 == s2:
                    print("{:<50}\t==\t{:<50}".format(s1,s2))
                else:
                    print("{:<50}\t!=\t{:<50}".format(s1,s2))
                idx2+=1
                last_idx2=idx2
            idx1+=1
        while(idx2<len(func_s2)):
            print("{:<50}\t->\t{:<50}".format("",func_s2[idx2].pp_str(state=state2, concretize=True)))
            idx2+=1

angr.AnalysesHub.register_default('siminvocationscompare', SimInvocationsCompare)
# Project
p = angr.Project(sys.argv[1], load_options={"auto_load_libs":False})
# Normalized for decompilation
cfg = p.analyses.CFGFast(normalize=True)
# From begining
state = p.factory.entry_state()
sm = p.factory.simulation_manager(state)
# Until find a print
func = cfg.functions.get('printf')
found = sm.explore(find=func.addr,num_find=2)
p.analyses.siminvocationscompare(found.found[0], found.found[1])
# get first decision point
decision_func1 = found.found[0].history.simprocs.hardcopy[0]
decision_func2 = found.found[1].history.simprocs.hardcopy[1]
# Update state for the current one
decision_func1.set_state(found.found[0])
decision_func2.set_state(found.found[1])
# get handler to this func in the original cfg
cfg_func = cfg.functions.get(decision_func1.name)
# Concretized decompilation 1
dec = p.analyses.Decompiler(cfg_func,concrete_values=decision_func1)
open(sys.argv[1]+'.decompiler1.c','w').write(dec.codegen.text)       
#IPython.embed()
# get handler to this func in the original cfg
cfg_func = cfg.functions.get(decision_func2.name)
# Concretized decompilation 1
dec = p.analyses.Decompiler(cfg_func,concrete_values=decision_func2)
open(sys.argv[1]+'.decompiler2.c','w').write(dec.codegen.text)       
