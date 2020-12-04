import sys
import argparse
import requests
import bs4
import re
import logging
import pickle
logging.basicConfig(filename='simprocgen.log', level=logging.INFO)

class Knowledge:
    def __init__(self, type=None):
        self.type=type
        self.typesize = dict()
        self.typevalue = dict()

    def set_size_of(self, typename, typesize):
        self.typesize[typename] = typesize

    def set_value_of(self, typename, typevalue):
        self.typevalue[typename] = typevalue

    def get_size_of(self, typename):
        return self.typesize[typename]

    def get_value_of(self, typename):
        return self.typevalue[typename]

class WinKnowledge(Knowledge):
    def __init__(self):
        Knowledge.__init__(self, "Windows")
        self.set_size_of('HANDLE', 4*8)         # in bits
        self.set_size_of('BOOL',   4*8)         # in bits
        self.set_size_of('DWORD',  4*8)         # in bits
        self.set_size_of('void',   4*8)           # in bits
        self.set_value_of('HANDLE', "0x1337")   # random value
        self.set_value_of('BOOL', "True")       # random value
        self.set_value_of('DWORD', "0x1337")    # random value
        self.set_value_of('void', "")           # no value
        self.url = 'https://docs.microsoft.com/api/search?search=%s&locale=en-us&scope=Desktop'

    def look_for_api_url(self, api):
        r = requests.get(self.url % api)
        url = r.json()['results'][0]['url']
        return url

    def look_for_api(self, api, url):
        r = requests.get(url)
        s = bs4.BeautifulSoup(r.text,'html.parser')
        f = s.find("code")
        logging.info(f.get_text())
        return f.get_text()

class LinuxKnowledge(Knowledge):
    def __init__(self):
        Knowledge.__init__(self, "Windows")
        self.set_size_of('HANDLE', 4*8)         # in bits
        self.set_size_of('BOOL',   4*8)         # in bits
        self.set_size_of('DWORD',  4*8)         # in bits
        self.set_size_of('void',   4*8)         # in bits
        self.set_size_of('int',    4*8)         # in bits
        self.set_size_of('long',   4*8)         # in bits
        self.set_size_of('enum',   4*8)         # in bits
        self.set_size_of('pid_t',  4*8)         # in bits
        self.set_size_of('char',  1*8)          # in bits
        self.set_value_of('HANDLE', "0x1337")   # random value
        self.set_value_of('BOOL', "True")       # random value
        self.set_value_of('DWORD', "0x1337")    # random value
        self.set_value_of('void', "")           # no value
        self.set_value_of('long', "0x1337")     # no value
        self.set_value_of('int', "0x1337")      # no value
        self.url = "https://linux.die.net/man/%d/%s"

    def look_for_api_url(self, api):
        for idx in range(0,10):
            search_url = self.url % (idx,api)
            r = requests.get(search_url)
            if r.status_code == 200:
                break
        return search_url

    def look_for_api(self, api, url):
        r = requests.get(url)
        s = bs4.BeautifulSoup(r.text,'html.parser')
        f = s.find("pre")
        for line in f.get_text().replace("\n*"," *").split(";"):
            func = re.sub(' +', ' ',line.split("\n")[-1])
            if "include" not in func and len(func)>0 and api in func:
                prototype = func.replace("*","").strip()
                logging.info(prototype)
                return prototype

class API:
    def __init__(self, name, ret, args, kb, concretize=False):
        self.name = name
        self.ret = ret
        self.void = self.__check_void()
        self.__set_args(args)
        if concretize:
            self.__set_concrete_sizes(args, kb)

    def __check_void(self):
        return True if self.ret == "void" else False

    def __set_concrete_sizes(self, args, kb):
        self.ret_size = kb.get_size_of(self.get_return())
        self.args_size = dict()
        for arg in args:
            self.args_size[arg[1]] = kb.get_size_of(arg[0])

    def __set_args(self, args):
        self.arg_types = dict()
        self.arg_names = []
        for arg in args:
            self.arg_names.append(arg[1])
            self.arg_types[arg[1]]=arg[0]

    def get_name(self):
        return self.name

    def get_return(self):
        return self.ret

    def get_args(self):
        return self.arg_names

    def get_arg_type(self, arg):
        return self.arg_types[arg]

    def get_arg_size(self, arg):
        return self.arg_size[arg]

class SimProcGen:
    def __init__(self, kb=None):
        self.kb = kb
  
    def get_symbols_string(self, api):
        ret_size = self.kb.get_size_of(api.get_return())
        ret_str = "rval = self.state.solver.BVS(%s, %d, key=('api', %s))" % (api.get_name(), ret_size, api.get_name())
        return ret_str

    def gen_sim_proc(self, api, symbolize=False):
        declaration = "class %s(angr.SimProcedure):\n" % api.get_name()
        args = ["self"]
        [args.append(arg) for arg in api.get_args()]
        run_method = "\tdef run(%s):\n" % ','.join(args)
        if symbolize is True:
            if api.void:
                logging.warning("Can't Symbolize Void Functions!")
                ret_stmt = "\t\treturn"
            else:
                ret_stmt = "\t\t" + self.get_symbols_string(api)
                ret_stmt += "\n\t\treturn rval"
        else:
            ret_stmt = "\t\treturn %s" % kb.get_value_of(api.get_return())
        sim_proc_string = declaration + run_method + ret_stmt
        logging.info(sim_proc_string)
        return sim_proc_string

    def __parse_api(self, api, concretize=False):
        normalized_api = ' '.join(api.split(" ")[1:]) if api.startswith("_") else api
        ret = normalized_api.split(" ")[0]
        name = normalized_api.split(" ")[1].split("(")[0]
        args=[]
        for arg in normalized_api.split("(")[1].split(")")[0].split(","):
            arg_tokens = arg.strip().split(" ")
            token1 = arg_tokens[0]
            if "const" in token1:
                arg_type = arg_tokens[-2]
            else:
                arg_type = token1
            arg_name = arg_tokens[-1]
            if arg_type !='' and arg_name !='':
                args.append((arg_type,arg_name))
        return API(name,ret,args, self.kb, concretize)
    
    def introspect_api(self, api, concretize=False):
        api_name = api.lower()
        _url = self.kb.look_for_api_url(api_name)
        _api = self.kb.look_for_api(api, _url)
        _api_h = self.__parse_api(_api, concretize)
        if concretize:
            pickle.dump(_api_h,open("%s.pickle" % api,'wb'))
        return _api_h

parser = argparse.ArgumentParser(description='Generate Angr SimProcedures')
parser.add_argument('-t', "--type", help='Set Environment')
parser.add_argument('-a', "--api", type=str, help='API to search for')
parser.add_argument("--symbolize", action="store_true", help='Set function return as Symbolic')
parser.add_argument("--concretize", action="store_true", help='Generate API with concrete sizes')
p = parser.parse_args(sys.argv[1:])
if p.type == "Windows":
    kb = WinKnowledge()
elif p.type == "Linux":
    kb = LinuxKnowledge()
else:
    raise ValueError("No Knowledge Database")
spg = SimProcGen(kb)
api = spg.introspect_api(p.api, p.concretize)
print(spg.gen_sim_proc(api, p.symbolize))
