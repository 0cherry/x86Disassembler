from capstone import *
from info import *
from collections import OrderedDict
import copy

p_base = 0x00400000
# p_name, p_RVA, p_offset, p_code = 'uncompress', 0x11250, 0x11250, '558BEC83EC3C8B45108945C48B4D14894DC88B55C83B5514740AB8FBFFFFFFE9AC0000008B45088945D08B4D0C8B118955D48B450C8B4DD43B08740AB8FBFFFFFFE98A000000C745E400000000C745E8000000006A3868C4754D5A8D55C452E85793FFFF83C40C8945FC837DFC0074058B45FCEB5B6A048D45C450E8F893FFFF83C4088945FC837DFC01742A8D4DC451E841B8FFFF83C404837DFC02740C837DFCFB750D837DC8007507B8FDFFFFFFEB1F8B45FCEB1A8B550C8B45D889028D4DC451E80FB8FFFF83C4048945FC8B45FC8BE55DC3'
p2_name, p2_RVA, p2_offset, p2_code = 'max', 0x1450, 0x1450, '558bec8b45083b450c7e078b4508eb05eb038b450c5dc3'
# p2_name, p2_RVA, p2_offset, p2_code = 'max', 0x1450, 0x1450, '558bec8b45083b450c7d078b4508eb05eb038b450c5dc3'
p1_name, p1_RVA, p1_offset, p1_code = 'min', 0x14d0, 0x14d0, '558bec8b45083b450c7d078b4508eb05eb038b450c5dc3'
p1_code = bytearray.fromhex(p1_code)
p2_code = bytearray.fromhex(p2_code)

p_mode = Cs(CS_ARCH_X86, CS_MODE_32)
p_mode.detail = True


class Block:
    def __init__(self, start_instruction=None):
        self.block_number = 0
        self.prev = list()
        self.cond_next = None
        self.next = None
        self.constraint = None
        self.cmp = None
        self.instructions = list()
        if start_instruction is not None:
            self.id = start_instruction.address
            self.instructions.append(start_instruction)
        self.status = dict()

    def __deepcopy__(self, memo):
        not_there = []
        existing = memo.get(self, not_there)
        if existing is not not_there:
            return existing
        dup = Block(self.instructions[0])
        memo[self] = dup
        for c in self.prev:
            dup.prev.append(copy.deepcopy(c))
        if self.cond_next is not None:
            dup.cond_next = copy.deepcopy(self.cond_next)
        if self.next is not None:
            dup.next = copy.deepcopy(self.next)
        dup.constraint = self.constraint
        dup.instructions = self.instructions
        return dup

    def copy(self):
        copy_block = Block(self.instructions[0])
        copy_block.block_number = self.block_number
        copy_block.prev = self.prev[:]
        if self.cond_next is not None:
            copy_block.cond_next = self.cond_next.copy()
        if self.next is not None:
            copy_block.next = self.next.copy()
        copy_block.constraint = self.constraint
        copy_block.instructions = self.instructions[:]
        return copy_block

    def set_id(self, start_address):
        self.id = start_address

    def set_block_number(self, number):
        self.block_number = number

    def add_prev(self, block):
        self.prev.append(block)

    def set_cond_next(self, block):
        self.cond_next = block

    def set_next(self, block):
        self.next = block

    def set_constraint(self, inst):
        self.constraint = inst

    def set_cmp(self, cmp_inst):
        self.cmp = cmp_inst

    def add_instruction(self, inst):
        self.instructions.append(inst)

    def get_last(self):
        body_len = len(self.instructions)
        if body_len == 0:
            return None
        else:
            return self.instructions[body_len - 1]

    def get_mnemonics(self):
        mnemonics = []
        for inst in self.instructions:
            mnemonics.append(inst.mnemonic)
        return mnemonics


def copy_block_cond_list(lst):
    copied_list = list()
    for [block, cond] in lst:
        copied_list.append([block, cond])
    return copied_list


def trace(target):
    available_paths = []

    def _trace(block, sub_path):
        sub_path.append([block, False])
        # sub_path.append(b)
        next_block = block.next
        cond_next = block.cond_next
        if next_block is None:
            available_paths.append(sub_path[:])
        elif next_block is not None:
            # p = sub_path[:]
            p = copy_block_cond_list(sub_path)
            if next_block not in sub_path:
                _trace(next_block, p)
        if cond_next is not None:
            p = copy_block_cond_list(sub_path)
            if cond_next not in sub_path:
                p[-1][-1] = True
                _trace(cond_next, p)

    # available_path_by_block = _backtrace(block, [], all_paths)
    _trace(target, [])
    return available_paths


def print_state(output_state):
    state_keys = output_state.keys()
    print('{')
    for state_key in state_keys:
        print('\t{} : {}'.format(state_key, output_state[state_key]))
    print('}')


def print_path(path):
    for index, [block, condition] in enumerate(path):
        print("block%d " % block.block_number),
        if block.cmp is not None and block.constraint is not None:
            print block.get_mnemonics()[:-2]
            print("%s" % block.cmp.mnemonic),
            print("%s" % block.cmp.op_str)
            print("%s" % block.constraint.mnemonic),
            print("%s" % block.constraint.op_str),
            print("%s" % condition)
        else:
            print block.get_mnemonics()

        for instruction in block.instructions:
            print("0x%08X:" % instruction.address),
            print("%s" % instruction.mnemonic),
            if len(instruction.mnemonic) < 3:
                print("\t\t%s" % instruction.op_str)
            else:
                print("\t%s" % instruction.op_str)
    print('')


def refine_path(path):
    output_state = OrderedDict()
    state_keys = ['eax', 'ecx', 'edx', 'ebx', 'ebp', 'esp']
    for key in state_keys:
        output_state[key] = 'external_input_{}'.format(key)
        if key == 'esp':
            output_state[key] = 0
    output_state['constraint'] = []
    output_state['stack'] = []
    output_state['heap'] = {}

    def search_status(_instruction, _operand):
        reg = _operand.reg
        if reg < 1:
            # [base + disp] form or pointer?
            base_reg = _instruction.reg_name(_operand.mem.base)
            if base_reg == 'ebp':
                offset = int(_operand.mem.disp)
                if offset > 0:
                    return 'arg{}'.format(offset / 4 - 1)
                else:
                    return output_state['stack'][abs(offset) / 4 - 1]
        elif reg < 1300:
            # register
            return output_state[_instruction.reg_name(reg)]
        else:
            # address
            # print("\t\t\t%s" % reg)
            return reg

    for [block, condition] in path:
        variable1, variable2 = None, None
        for instruction in block.instructions:
            operator = instruction.mnemonic
            operands = instruction.operands
            if operator == 'push':
                operand = operands[0]
                output_state['esp'] -= 4
                output_state['stack'].append(search_status(instruction, operand))
            elif operator == 'mov':
                operand1, operand2 = operands[0], operands[1]
                output_state[instruction.reg_name(operand1.reg)] = search_status(instruction, operand2)
            elif operator == 'cmp':
                operand1, operand2 = operands[0], operands[1]
                variable1, variable2 = search_status(instruction, operand1), search_status(instruction, operand2)
            elif operator == 'pop':
                operand = operands[0]
                output_state['esp'] += 4
                output_state[instruction.reg_name(operand.reg)] = output_state['stack'].pop()
            elif operator in cjmp_instructions:
                constraint_equation = cjmp_equations[operator]
                constraint_expression = '{} {} {}'.format(variable1, constraint_equation, variable2)
                output_state['constraint'].append((constraint_expression, condition))
            else:
                continue
            # print output_state
    return output_state


def disassemble(mode, base, name, rva, offset, code):
    print("===== %s =====" % name)
    # for instruction in mode.disasm(code, base + rva):
    #     print("0x%08X:" % instruction.address),
    #     print("%s" % instruction.mnemonic),
    #     if len(instruction.mnemonic) < 3:
    #         print("\t\t%s" % instruction.op_str)
    #     else:
    #         print("\t%s" % instruction.op_str)
        # print(instruction.id)
        # print("\t\t%s" % instruction.regs_read)
        # for reg in instruction.regs_read:
        #     print("\t\t\t%s" % instruction.reg_name(reg))
        # print("\t\t%s" % instruction.regs_write)
        # for reg in instruction.regs_write:
        #     print("\t\t\t%s" % instruction.reg_name(reg))
        # print("\t\t%s" % instruction.groups)
        # for g in instruction.groups:
        #     print("\t\t\t%s" % g)
        # print("\t\t%s" % instruction.operands)
        # for opnd in instruction.operands:
            # print type(opnd)
            # opnd_value_reg = opnd.reg
            # if opnd_value_reg < 1:
            #     print("\t\t\t%s + %d" % instruction.reg_name(opnd.mem.base), opnd.mem.index)
            #     print('\t\t\t{} + {}'.format(instruction.reg_name(opnd.mem.base), hex(int(opnd.mem.disp))))
                # print type(opnd.mem.disp)
            # elif opnd_value_reg < 1300:
            #     continue
                # register
                # print("\t\t\t%s" % instruction.reg_name(opnd.value.reg))
            # else:
            #     continue
                # address
                # print("\t\t\t%s" % opnd_value_reg)
        # print type(instruction)
    # print("===== end of function =====")

    function = OrderedDict()
    mnemonic_list = list()
    leader_address_set = set()
    basic_blocks = OrderedDict()

    for instruction in mode.disasm(code, base + rva):
        function[instruction.address] = instruction
        mnemonic_list.append(instruction.mnemonic)
    # for k, v in function.items():
    #     print(k, v)

    # find block leader
    inst_keys = function.keys()
    leader_address_set.add(function[inst_keys[0]].address)
    for j in range(1, len(inst_keys)):
        mnemonic = function[inst_keys[j]].mnemonic
        if mnemonic == jmp_instruction or mnemonic in cjmp_instructions:
            # leader_list.append(int(function[i].op_str[2:], 16) & 0x0000FFFF)
            for instruction in function.values():
                try:
                    if instruction.address == int(function[inst_keys[j]].op_str[2:], 16):
                        leader_address_set.add(instruction.address)
                except ValueError:
                    continue
            if j < len(function) - 1:
                leader_address_set.add(function[inst_keys[j + 1]].address)
    # leader_address_sorted_set = sorted(leader_address_set)

    # create basic block
    bb = Block(function.values()[0])
    bb.set_block_number(0)
    block_number = 1
    for j in range(1, len(inst_keys)):
        inst = function[inst_keys[j]]
        if inst.address in leader_address_set:
            basic_blocks[bb.id] = bb
            bb = Block(inst)
            bb.set_block_number(block_number)
            block_number += 1
        else:
            bb.instructions.append(inst)
        if inst.mnemonic == 'cmp':
            bb.set_cmp(inst)
        if inst.mnemonic in cjmp_instructions or inst.mnemonic == 'jmp':
            bb.set_constraint(inst)
    basic_blocks[bb.id] = bb

    bb_keys = basic_blocks.keys()
    # generate CFG
    for j in range(len(bb_keys)):
        current_block = basic_blocks[bb_keys[j]]
        end_of_block = current_block.get_last()
        # case of jmp
        if end_of_block.mnemonic == jmp_instruction:
            try:
                target_block = basic_blocks[int(end_of_block.op_str[2:], 16)]
                target_block.add_prev(current_block)
                current_block.set_next(target_block)
            except ValueError:
                pass
        # case of cond_jmp
        if end_of_block.mnemonic in cjmp_instructions:
            try:
                target_block = basic_blocks[int(end_of_block.op_str[2:], 16)]
                target_block.add_prev(current_block)
                current_block.set_cond_next(target_block)
            except ValueError:
                pass
        # case excluding jmp
        if end_of_block.mnemonic != jmp_instruction:
            try:
                target_block = basic_blocks[bb_keys[j + 1]]
                target_block.add_prev(current_block)
                current_block.set_next(target_block)
            except IndexError:
                pass

    # back-trace CFG excluding loop
    # backward_paths = backtrace(basic_blocks[bb_keys[-1]])

    # trace CFG excluding loop
    forward_paths = trace(basic_blocks[bb_keys[0]])

    '''
    # print path
    print("======= function name : %s =======" % name)
    for index, path in enumerate(forward_paths):
        print("<< path %d >>" % (index + 1))
        print_path(path)
    print("======= function name : %s =======" % name)
    '''

    # refine path
    outputs = []
    for path in forward_paths:
        outputs.append(refine_path(path))

    for output in outputs:
        # print_state(output)
        print(output['constraint'])
        print(output['eax'])
    '''
    if 4 < len(leader_set) < 11:
        print("===== %s =====" % name)
        for instruction in function:
            if instruction in leader_set:
                print("%04X:\t" % instruction.address),
            else:
                print("\t\t\t"),
            print("0x%04X:" % instruction.address),
            print("%s" % instruction.mnemonic),
            print("%s" % instruction.op_str)
        print("===== end of function =====")
    '''
    # print("===== %s =====" % name)
    # for constraint in constraint_list:
    #     print constraint
    # print("===== end of function =====")

disassemble(p_mode, p_base, p2_name, p2_RVA, p2_offset, p2_code)
disassemble(p_mode, p_base, p1_name, p1_RVA, p1_offset, p1_code)