jmp_instruction = 'jmp'
cjmp_instructions = ['jo', 'jno', 'js', 'jns', 'je', 'jz', 'jne', 'jnz', 'jb', 'jnae', 'jc', 'jnb', 'jae', 'jnc',
                     'jbe', 'jna', 'ja', 'jnbe', 'jl', 'jnge', 'jge', 'jnl', 'jle', 'jng', 'jg', 'jnle', 'jp', 'jpe',
                     'jnp', 'jpo', 'jcxz', 'jecxz']
cjmp_equations = {'jo': '',
                  'jno': '',
                  'js': '',
                  'jns': '',
                  'je': '==',
                  'jz': '==',
                  'jne': '!=',
                  'jnz': '!=',
                  'jb': '',
                  'jnae': '',
                  'jc': '',
                  'jnb': '',
                  'jae': '',
                  'jnc': '',
                  'jbe': '',
                  'jna': '',
                  'ja': '',
                  'jnbe': '',
                  'jl': '<',
                  'jnge': '<',
                  'jge': '>=',
                  'jnl': '>=',
                  'jle': '<=',
                  'jng': '<=',
                  'jg': '>',
                  'jnle': '>',
                  'jp': '',
                  'jpe': '',
                  'jnp': '',
                  'jpo': '',
                  'jcxz': '',
                  'jecxz': ''
                  }

flag_o_jmp_instructions = ['jo', 'jno']
flag_s_jmp_instructions = ['js', 'jns']
flag_z_jmp_instructions = ['je', 'jz', 'jne', 'jnz']
flag_c_jmp_instructions = ['jb', 'jnae', 'jc', 'jnb', 'jae', 'jnc']
flag_cz_jmp_instructions = ['jbe', 'jna', 'ja', 'jnbe']
flag_so_jmp_instructions = ['jl', 'jnge', 'jge', 'jnl']
flag_zso_jmp_instructions = ['jle', 'jng', 'jg', 'jnle']
flag_p_jmp_instructions = ['jp', 'jpe', 'jnp', 'jpo']
cxz_instructions = ['jcxz', 'jecxz']

flag_instructions = ['adc', 'add', 'and', 'clc', 'cld', 'cli', 'cmc', 'cmp', 'cmps', 'dec', 'div', 'idiv',
                     'imul', 'inc', 'int', 'into', 'iret', 'mul', 'neg', 'or', 'popf', 'rcl', 'rcr', 'rol',
                     'ror', 'sal', 'shl', 'sar', 'sbb', 'scas', 'stc', 'std', 'sti', 'sub', 'test',
                     'xor']

jmp_instruction_flag_pair = {
    'adc': ['C', 'O', 'S', 'P', 'Z'],
    'add': ['C', 'O', 'S', 'P', 'Z'],
    'and': ['C', 'O', 'S', 'P', 'Z'],
    'clc': ['C'],
    'cmc': ['C'],
    'cmp': ['C', 'O', 'S', 'P', 'Z'],
    'cmps': ['C', 'O', 'S', 'P', 'Z'],
    'dec': ['O', 'S', 'P', 'Z'],
    'div': ['C', 'O', 'S', 'P', 'Z'],
    'idiv': ['C', 'O', 'S', 'P', 'Z'],
    'imul': ['C', 'O', 'S', 'P', 'Z'],
    'inc': ['O', 'S', 'P', 'Z'],
    'iret': ['C', 'S', 'P', 'Z'],
    'mul': ['C', 'O', 'S', 'P', 'Z'],
    'neg': ['C', 'O', 'S', 'P', 'Z'],
    'or': ['C', 'O', 'S', 'P', 'Z'],
    'popf': ['C', 'O', 'S', 'P', 'Z'],
    'rcl': ['C', 'O'],
    'rol': ['C', 'O'],
    'ror': ['C', 'O'],
    'sal': ['C', 'O', 'S', 'P', 'Z'],
    'shl': ['C', 'O', 'S', 'P', 'Z'],
    'sar': ['C', 'O', 'S', 'P', 'Z'],
    'sbb': ['C', 'O', 'S', 'P', 'Z'],
    'scas': ['C', 'O', 'S', 'P', 'Z'],
    'stc': ['C'],
    'sub': ['C', 'O', 'S', 'P', 'Z'],
    'test': ['C', 'O', 'S', 'P', 'Z'],
    'xor': ['C', 'O', 'S', 'P', 'Z'],
}
