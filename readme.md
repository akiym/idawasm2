# idawasm

These IDA Pro plugins add support for loading and disassembling WebAssembly modules.


Features:

  - control flow reconstruction and graph mode
  - code and data cross references
  - globals, function parameters, local variables, etc. can be renamed
  - auto-comment hint suport
  
  
#### recognizes WebAssembly modules

![load-wasm](img/load-wasm.png)


#### reconstructs control flow

![graph-mode](img/graph-mode.png)

#### parses and renders types

![render-prototype](img/render-prototype.png)

#### extracts code and data cross references

![drefs](img/drefs.png)

#### detect function frame layout (for LLVM-compiled binaries)

![drefs](img/frame.png)

  
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

This plugin was developed against IDA 7.1, but probably works with IDA 7.0+.

## todo

- [ ] name locations
- [ ] mark data xref to memory load/store
- [ ] mark xref to imports
- [ ] compute stack deltas
- [ ] add entry point for start function (need to see an example)

## acknowledgements

This project relies on the [athre0z/wasm](https://github.com/athre0z/wasm) WebAssembly decoder and disassembler library for Python.
