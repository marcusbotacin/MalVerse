import angr
import sys
import IPython

def emit_code(value):
    print("#include <unistd.h> \n \
#include<stdio.h> \n \
#include<stdlib.h> \n \
#include<string.h> \n \
static void init(void) __attribute__((constructor)); \n \
#define STR %s \n \
void *addr; \n \
static void init(void) \n \
{ \n \
   addr=(char*)malloc(100); \n \
   strcpy(addr,STR); \n \
} \n \
char *getcwd(char *buf, size_t size) \n \
{ \n \
    return addr; \n \
} \n \
" % value)

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
# this will be the decompiler target
ftarget = cfg.functions.get(decision_func.name)
# Warn User
decision_func2 = found.found[0].history.simprocs.hardcopy[1]
decision_func2.set_state(found.found[0])
ARG = decision_func2.pp_str(concretize=True).split("(")[1].split(",")[0]
emit_code(ARG)
open(sys.argv[1]+'.decompiler.c','w').write(p.analyses.Decompiler(func=ftarget,cfg=cfg,concrete_values=decision_func).codegen.text)
