from capstone import *
from info import *
from collections import OrderedDict
from z3 import *
import copy


class Block:
    def __init__(self, start_instruction=None):
        self.block_number = 0
        self.prev = list()
        self.cond_next = None
        self.next = None
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


def disassemble(mode, base, name, rva, offset, code):
    # print("===== %s =====" % name)
    # print_instructions()

    function = OrderedDict()
    for instruction in mode.disasm(code, base + rva):
        function[instruction.address] = instruction

    return function


def pprint_instruction(instruction):
    print("0x%08X:" % instruction.address),
    print("%s" % instruction.mnemonic),
    if len(instruction.mnemonic) < 3:
        print("\t\t%s" % instruction.op_str)
    else:
        print("\t%s" % instruction.op_str)


def pprint_instructions(function):
    for k, instruction in function.items():
        pprint_instruction(instruction)


def find_block_leader(function, leader_address_set):
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


def create_basic_block(basic_blocks, function, leader_address_set):
    # create basic block using leader block
    inst_keys = function.keys()
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
        # if inst.mnemonic == 'cmp':
        #     bb.set_cmp(inst)
        # if inst.mnemonic in cjmp_instructions or inst.mnemonic == 'jmp':
        #     bb.set_constraint(inst)
    basic_blocks[bb.id] = bb


def generate_cfg(basic_blocks):
    bb_keys = basic_blocks.keys()
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


# trace CFG excluding loop
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

    _trace(target, [])
    return available_paths


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
    status = OrderedDict()
    state_keys = ['eax', 'ecx', 'edx', 'ebx', 'ebp', 'esp']
    for key in state_keys:
        status[key] = ['value', 'unknown']
        if key == 'esp':
            status[key] = ['stack_pointer', 0]
        if key == 'ebp':
            status[key] = ['base_pointer', 0]
    status['constraint'] = []
    status['stack'] = []
    status['heap'] = {}

    def get_storage_space(_instruction, _operand):
        if _operand is None:
            return

        op_type = _operand.type
        reg = _operand.reg
        if op_type == 0:
            # invalid
            return
        elif op_type == 1:
            # register
            return ['register', _instruction.reg_name(reg)]
        elif op_type == 2:
            # immediate
            return ['value', reg]
        elif op_type == 3:
            # memory
            # memory syntax - segment:[base + index * scale + displacement] == segment:displacement(base, index, scale)
            # segment : segment register
            # base, index : general-purpose register
            # scale : 1, 2, 4 or 8 (default 1)
            # displacement : 8-, 16-, or 32-bit value
            # segment = _instruction.reg_name(_operand.mem.segment)
            base = (status[_instruction.reg_name(_operand.mem.base)] if _operand.mem.base != 0 else ['value', 0])
            index = (status[_instruction.reg_name(_operand.mem.index)] if _operand.mem.index != 0 else ['value', 0])
            scale = ['value', int(_operand.mem.scale)]
            displacement = ['value', int(_operand.mem.disp)]
            # print base + index * scale + displacement
            # print ['pointer', lookup_status(base), lookup_status(index), scale, displacement]
            base, index = lookup_status(base), lookup_status(index)
            return ['memory', [base, index, scale, displacement]]
        elif op_type == 4:
            # fp
            # not implemented
            return

    def lookup_status(_storage_space):
        if type(_storage_space) is not list:
            return

        case = _storage_space[0]
        if case == 'register':
            register_name = _storage_space[1]
            return status[register_name]
        elif case == 'memory':
            memory = _storage_space[1]
            base = memory[0]
            index = memory[1]
            # scale = memory[2][1]
            displacement = memory[3][1]
            if base[0] == 'stack_pointer' and index[0] == 'value':
                # To do
                if base[1] + displacement > 0:
                    return ['parameter', 'arg{}'.format((base[1] + displacement) / 4)]
                else:
                    return status['stack'][abs(base[1] + displacement) / 4]
            elif base == 'esp':
                return _storage_space
        elif case == 'value':
            return _storage_space
        else:
            return _storage_space

    for [block, condition] in path:
        variable1, variable2 = None, None
        for instruction in block.instructions:
            operator = instruction.mnemonic
            operands = instruction.operands
            # operand1 must be matched register name or memory location, but in case of cmp must be matched value
            # operand2 must be matched value
            if operator == 'push':
                operand = operands[0]
                storage_space = get_storage_space(instruction, operand)
                status['stack'].append(lookup_status(storage_space))
                status['esp'][-1] -= 4
            elif operator == 'pop':
                operand = operands[0]
                storage_space = get_storage_space(instruction, operand)[1]
                status[storage_space] = status['stack'].pop()
                status['esp'][-1] += 4
            elif operator == 'mov':
                operand1, operand2 = operands[0], operands[1]
                storage_space1 = get_storage_space(instruction, operand1)
                storage_space2 = get_storage_space(instruction, operand2)
                status[storage_space1[1]] = lookup_status(storage_space2)
            elif operator == 'cmp':
                operand1, operand2 = operands[0], operands[1]
                storage_space1 = get_storage_space(instruction, operand1)
                storage_space2 = get_storage_space(instruction, operand2)
                variable1, variable2 = lookup_status(storage_space1), lookup_status(storage_space2)
            elif operator in cjmp_instructions:
                constraint_equation = cjmp_equations[operator]
                constraint_expression = '{} {} {}'.format(variable1[1], constraint_equation, variable2[1])
                status['constraint'].append((constraint_expression, condition))
            elif operator == 'lea':
                operand1, operand2 = operands[0], operands[1]
                storage_space1 = get_storage_space(instruction, operand1)
                storage_space2 = get_storage_space(instruction, operand2)
                status[storage_space1[1]] = storage_space2
            else:
                continue
    return status


def print_status(output_status):
    state_keys = output_status.keys()
    print('{')
    for state_key in state_keys:
        if state_key == 'stack':
            print('\t{} :'.format(state_key))
            for value in output_status[state_key]:
                print('\t\t{}'.format(value))
        else:
            print('\t{} : {}'.format(state_key, output_status[state_key]))
    print('}')


def refine(function):
    leader_address_set = set()
    basic_blocks = OrderedDict()
    find_block_leader(function, leader_address_set)
    create_basic_block(basic_blocks, function, leader_address_set)
    generate_cfg(basic_blocks)

    root = basic_blocks.keys()[0]
    forward_paths = trace(basic_blocks[root])

    _outputs = []
    for path in forward_paths:
        _outputs.append(refine_path(path))

    return _outputs

    # print path
    # for index, path in enumerate(forward_paths):
    #     print_path(path)

    # print status
    # for output in _outputs:
    #     print_status(output)


def solve_by_z3():
    # z3 Solver
    arg1 = Int('arg1')
    arg2 = Int('arg2')
    ret = Int('ret')
    constraint1 = outputs1[0]['constraint'][0][0]
    if outputs1[0]['constraint'][0][1]:
        true_statement1, false_statement1 = outputs1[0]['eax'][1], outputs1[1]['eax'][1]
    else:
        true_statement1, false_statement1 = outputs1[1]['eax'][1], outputs1[0]['eax'][1]

    # constraint2 = outputs2[0]['constraint'][0][0]
    # if outputs2[0]['constraint'][0][1]:
    #     true_statement2, false_statement2 = outputs2[0]['eax'][1], outputs2[1]['eax'][1]
    # else:
    #     true_statement2, false_statement2 = outputs2[1]['eax'][1], outputs2[0]['eax'][1]
    #
    solver = Solver()
    expression1 = 'If({}, ret=={}, ret=={})'.format(constraint1, true_statement1, false_statement1)
    # expression2 = '{}, ret=={}, ret=={}'.format(constraint2, true_statement2, false_statement2)
    solver.add(eval(expression1))
    # solver.add(eval(expression2))
    solver.add(arg1 != arg2)
    if str(solver.check()) == 'sat':
        print(solver.model())
    elif str(solver.check()) == 'unsat':
        print('no solution')

        # function3 = disassemble(p_mode, p_base, p3_name, p3_RVA, p3_offset, p3_code)
        # print('===== {} function ====='.format(p3_name))
        # pprint_instructions(function3)
        # refine(function3)

        # function4 = disassemble(p_mode, p_base, p4_name, p4_RVA, p4_offset, p4_code)
        # print('===== {} function ====='.format(p4_name))
        # pprint_instructions(function4)
        # for k, instruction in function4.items():
        #     operator = instruction.mnemonic
        #     operands = instruction.operands
        #     operand = operands[0]
        #     print instruction.id,\
        #         operand.type,\
        #         operand.value,\
        #         operand.size,\
        #         operand.reg, \
        #         operand.imm, \
        #         operand.fp
        #     print instruction.reg_name(operand.reg)
        # refine(function4)


if __name__ == '__main__':
    p_base = 0x00400000
    # p_name, p_RVA, p_offset, p_code = 'uncompress', 0x11250, 0x11250,
    # '558BEC83EC3C8B45108945C48B4D14894DC88B55C83B5514740AB8FBFFFFFFE9AC0000008B45088945D08B4D0C8B118955D48B450C8B4DD43B08740AB8FBFFFFFFE98A000000C745E400000000C745E8000000006A3868C4754D5A8D55C452E85793FFFF83C40C8945FC837DFC0074058B45FCEB5B6A048D45C450E8F893FFFF83C4088945FC837DFC01742A8D4DC451E841B8FFFF83C404837DFC02740C837DFCFB750D837DC8007507B8FDFFFFFFEB1F8B45FCEB1A8B550C8B45D889028D4DC451E80FB8FFFF83C4048945FC8B45FC8BE55DC3'
    p2_name, p2_RVA, p2_offset, p2_code = 'max', 0x1450, 0x1450, '558bec8b45083b450c7e078b4508eb05eb038b450c5dc3'
    # p2_name, p2_RVA, p2_offset, p2_code = 'max', 0x1450, 0x1450, '558bec8b45083b450c7d078b4508eb05eb038b450c5dc3'
    p1_name, p1_RVA, p1_offset, p1_code = 'min', 0x14d0, 0x14d0, '558bec8b45083b450c7d078b4508eb05eb038b450c5dc3'
    p3_name, p3_RVA, p3_offset, p3_code = 'get_crc_table', 0x1750, 0x1750, '558BEC8B450C506AFF8B4D0851E80500000083C40C5DC3'
    p4_name, p4_RVA, p4_offset, p4_code = 'subsequence', 0xf8de, 0xf8de, '558b6a01'

    p1_code = bytearray.fromhex(p1_code)
    p2_code = bytearray.fromhex(p2_code)
    p3_code = bytearray.fromhex(p3_code)
    p4_code = bytearray.fromhex(p4_code)

    p_mode = Cs(CS_ARCH_X86, CS_MODE_32)
    p_mode.detail = True

    # function1 = disassemble(p_mode, p_base, p2_name, p2_RVA, p2_offset, p2_code)
    # print('===== {} function ====='.format(p2_name))
    # pprint_instructions(function1)
    # outputs1 = refine(function1)
    # print_status(outputs1[0])
    # print_status(outputs1[1])

    # function2 = disassemble(p_mode, p_base, p1_name, p1_RVA, p1_offset, p1_code)
    # print('===== {} function ====='.format(p1_name))
    # outputs2 = refine(function2)
    # pprint_instructions(function2)
    # print_status(outputs2[0])
    # print_status(outputs2[1])

    function3 = disassemble(p_mode, p_base, p3_name, p3_RVA, p3_offset, p3_code)
    pprint_instructions(function3)

    # solve_by_z3()
