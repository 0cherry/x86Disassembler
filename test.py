from z3 import *

arg1 = Int('arg1')
arg2 = Int('arg2')
ret = Int('ret')

solver = Solver()
max_function = If(arg1 >= arg2, ret == arg1, ret == arg2)
solver.add(max_function)
# min_function = If(arg1 <= arg2, ret == arg1, ret == arg2)
# solver.add(min_function)

constraint = (arg1 != arg2)
solver.add(constraint)

if str(solver.check()) == 'sat':
    print(solver.model())
elif str(solver.check()) == 'unsat':
    print('no solution')

# max_function = And(Implies((a < b), c == b), Implies(Not(a < b), c == a))
# min_function = And(Implies((a < b), c == a), Implies(Not(a < b), c == b))

# str_expression = eval('arg1 * 2 <= arg2')
# print simplify(str_expression)
# print min_function
# print str_expression

# d = dict()
# mem1 = frozenset([['stack_pointer', -4], ['pointer', [['stack_pointer', -4], ['stack_pointer'], ['value', 2], ['value', 3]]], ['value', 1], ['value', 2]])
# mem2 = frozenset([['stack_pointer', -4], ['pointer', [['stack_pointer', -4], ['stack_pointer'], ['value', 2], ['value', 3]]], ['value', 1], ['value', 2]])
# d[mem1] = ['eax']
# d[mem2] = ['ebx']
# for k, v in d.items():
#     print '{} : {}'.format(k, v)
