# MalVerse

MalVerse proposes the use of Dynamic Symbolic Execution (DSE) to identify logic bombs in (mostly malicious) applications and automatically generates a patch library to be injected in the target application to allow it to be analyzed in typical sandbox solutions while triggering the logic bombing conditions.

# Author
MalVerse is developed by Marcus Botacin, under supervision of André Grégio, as a Proof of Concept (PoC) of an academic idea to be published in a paper.

# Directory Organization

* *Helpers*: Helper functions to generate traceable libraries.
* *Plugins*: Plugin to user MalVerse on Ghidra.
* *Tests*: Simple logic bombs to exercise our solution.

# Installation

## If you are experienced with DSEs
    
* Install [angr](https://github.com/angr/angr)
* Clone the [MalVerse branch](https://github.com/marcusbotacin/angr) and patch angr with it.

## If you need help

A Step-by-step guide:

### To Install Angr

* First, clone the [angr-dev repository](https://github.com/angr/angr-dev)
* Clone all repositories with *./setup.sh -C*
* Checkout to the versions that we used to generate the patch. The *do_checkout.sh* script might help.
* Install everything with *./setup.sh -i -e angr*
* Test it with *workon angr*. There is no MalVerse code here yet, everything should be working.

### Troubleshooting Virtualenv bugs

In some installations, the angr virtualenv is not properly set, in this case, do the following:

* *export WORKON_HOME=~/.virtualenvs*
* *VIRTUALENVWRAPPER_PYTHON='/usr/bin/python3'*
* *source `which virtualenvwrapper.sh`*

### Patching angr with MalVerse code

* Clone [our angr](https://github.com/marcusbotacin/angr/)
* Go to *branch MalVerse*
* Create a MalVerse branch in your angr repository
* From your angr repository, *git fetch our_angr_directory*
* Then patch *git merge FETCH_HEAD MalVerse*
* Your patched angr should be working!

