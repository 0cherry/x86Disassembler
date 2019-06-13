from capstone import *
from info import *
import pandas
from collections import OrderedDict
import copy


class Block:
    def __init__(self, start_instruction):
        self.block_number = 0
        self.id = start_instruction.address
        self.prev = list()
        self.cond_next = None
        self.next = None
        self.constraint = None
        self.condition = None
        self.instructions = list()
        self.instructions.append(start_instruction)

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

    def set_condition(self, cond):
        self.condition = cond

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
        next = block.next
        cond_next = block.cond_next
        if next is None:
            available_paths.append(sub_path[:])
        elif next is not None:
            # p = sub_path[:]
            p = copy_block_cond_list(sub_path)
            if next not in sub_path:
                _trace(next, p)
        if cond_next is not None:
            p = copy_block_cond_list(sub_path)
            if cond_next not in sub_path:
                p[-1][-1] = True
                _trace(cond_next, p)

    # available_path_by_block = _backtrace(block, [], all_paths)
    _trace(target, [])
    return available_paths


def backtrace(target):
    def _backtrace(block, sub_path, paths):
        sub_path.append(block)
        if len(sub_path[-1].prev) == 0:
            paths.append(sub_path[:])
        for prev in block.prev:
            p = sub_path[:]
            if prev in sub_path:
                continue
            else:
                _backtrace(prev, p, paths)

    available_paths = []
    # available_path_by_block = _backtrace(block, [], all_paths)
    _backtrace(target, [], available_paths)
    return available_paths


def print_path(path):
    for index, [block, condition] in enumerate(path):
        if block.condition is not None and block.constraint is not None:
            print("%s" % block.condition.mnemonic),
            print("%s" % block.condition.op_str)
            print("%s" % block.constraint.mnemonic),
            print("%s" % block.constraint.op_str),
            print("%s" % condition)
        print block.get_mnemonics()


mode = Cs(CS_ARCH_X86, CS_MODE_32)
mode.detail = True

file_path = "D:\FunctionExtractor\FunctionExtractor\zlib128.dll_export_func_info.csv"
# [function, RVA, offset, code, size]
data = pandas.read_csv(file_path)

base = 0x5a4c0000
for i in range(data['function'].count()):
    func_data = data.iloc[i:i+1, ]
    name = func_data['function'].tolist()[0]
    RVA = int(func_data['RVA'].tolist()[0], 16)
    offset = int(func_data['offset'].tolist()[0], 16)
    code = bytearray.fromhex(func_data['code'].tolist()[0])

    function = OrderedDict()
    mnemonic_list = list()
    leader_address_set = set()
    basic_blocks = OrderedDict()

    for instruction in mode.disasm(code, base + RVA):
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
                except ValueError as e:
                    continue
            if j < len(function)-1:
                leader_address_set.add(function[inst_keys[j + 1]].address)
    # leader_address_sorted_set = sorted(leader_address_set)

    # To debug
    if len(leader_address_set) != 5:
        continue

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
            bb.set_condition(inst)
        if inst.mnemonic in cjmp_instructions:
            bb.set_constraint(inst)
    basic_blocks[bb.id] = bb

    # generate CFG
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
            except ValueError as e:
                pass
        # case of cond_jmp
        if end_of_block.mnemonic in cjmp_instructions:
            try:
                target_block = basic_blocks[int(end_of_block.op_str[2:], 16)]
                target_block.add_prev(current_block)
                current_block.set_cond_next(target_block)
            except ValueError as e:
                pass
        # case excluding jmp
        if end_of_block.mnemonic != jmp_instruction:
            try:
                target_block = basic_blocks[bb_keys[j + 1]]
                target_block.add_prev(current_block)
                current_block.set_next(target_block)
            except IndexError as e:
                pass

    # back-trace CFG excluding loop
    # backward_paths = backtrace(basic_blocks[bb_keys[-1]])

    # trace CFG excluding loop
    forward_paths = trace(basic_blocks[bb_keys[0]])

    print("======= function name : %s =======" % name)
    for index, path in enumerate(forward_paths):
        print("<< path %d >>" % (index+1))
        print_path(path)
    print("======= function name : %s =======" % name)

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
