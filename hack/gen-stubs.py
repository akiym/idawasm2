import wasm.opcodes

with open('idawasm/processor.pyi', 'w') as f:
    print("class wasm_processor_t:", file=f)

    for op in wasm.opcodes.OPCODES:
        clean_mnem = op.mnemonic.replace('.', '_').replace('/', '_').upper()
        name = 'itype_' + clean_mnem
        print(f'{" " * 4}{name}: int', file=f)

    reg_names = []

    MAX_LOCALS = 0x1000
    for i in range(MAX_LOCALS):
        reg_names.append("$local%d" % (i))

    MAX_PARAMS = 0x1000
    for i in range(MAX_PARAMS):
        reg_names.append("$param%d" % (i))

    reg_names.append("SP")
    reg_names.append("CS")
    reg_names.append("DS")

    for i in range(len(reg_names)):
        name = 'ireg_' + reg_names[i].replace('$', '')
        print(f'{" " * 4}{name}: int', file=f)

for op in wasm.opcodes.OPCODES:
    name = 'OP_' + op.mnemonic.upper().replace('.', '_').replace('/', '_')
    print(f'{name}: Opcode')
