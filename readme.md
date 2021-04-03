# idawasm2

These IDA Pro plugins add support for loading and disassembling WebAssembly modules.

This version has been forked from [fireeye/idawasm](https://github.com/fireeye/idawasm) to enhance some features.

- IDA 7.6 support
- add Python 3 type annotations (partially for now)
- support `if`, `else`, `br_table` operations


Features:

  - control flow reconstruction and graph mode
  - code and data cross references
  - globals, function parameters, local variables, etc. can be renamed
  - auto-comment hint support
  
  
#### recognizes WebAssembly modules

![load-wasm](img/load-wasm.png)


#### reconstructs control flow

![graph-mode](img/graph-mode.png)

#### parses and renders types

![render-prototype](img/render-prototype.png)

#### extracts code and data cross references

![drefs](img/drefs.png)

#### detect function frame layout (for LLVM-compiled binaries)

![frame](img/frame.png)

  
## installation

There are three steps to install this loader and processor:

1. install the python module:
  
```
    python.exe setup.py install
```

2. manually install the WebAssembly file loader:
    
```
    mv loaders\wasm_loader.py %IDADIR%\loaders\wasm_loader.py
```

3. manually install the WebAssembly processor:
    
```
    mv procs\wasm_proc.py %IDADIR%\procs\wasm_proc.py
```

Whenever you update this project, you'll need to update the python module, but shouldn't have to touch the loader and processor files.

## supported IDA version

IDA 7.6 and Python 3.9 or later

## todo

- [ ] name locations
- [ ] mark data xref to memory load/store
- [ ] mark xref to imports
- [ ] compute stack deltas
- [ ] add entry point for start function (need to see an example)

## acknowledgements

[fireeye/idawasm](https://github.com/fireeye/idawasm) - Original version of this repository.

This project relies on the [athre0z/wasm](https://github.com/athre0z/wasm) WebAssembly decoder and disassembler library for Python.

## copyright

- Willi Ballenthin (original author of idawasm)
- Takumi Akiyama
