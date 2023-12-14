
# PE Inspector

Simple PE file inspector tool written in python. Supports searching functions by name in the IAT (Import Address Table) and supports searching functions by ordinal / name in the EAT (Export Address Table).



## Installation

Firstly clone the repository and ``cd`` into it. Then you can run ```python pei.py``` to get started using PEI.


## Guide

You can run ```python pei.py -h``` to learn more about using PEI. To simply list out all the headers , sections , directories in a file run ```python pei.py --file <FILE_PATH>```. To search for a function in the Import Address Table (IAT) run ```python pei.py --importsearch <FUNC_NAME>```. To search for a function in the Export Address Table (EAT) run ```python pei.py --exportsearch <FUNC_NAME> || <FUNC_ORDINAL>```. Dont forget to specify the file path!


