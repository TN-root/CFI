#!/usr/bin/env python
# coding=utf-8

' CFI漏洞自动发掘  '

__author__ = 'whichard'
import sys
import nose
import logging
import os
import string
import angr
import claripy
import time
import sys
import re
# from angrutils import *
import pdb
import copy
import time
import simuvex
from simuvex import abihint_global_list as agl

if __name__ == '__main__':
    # File=sys.argv[1]
    # b = angr.Project("File", load_options={'auto_load_libs': False})
    b = angr.Project("/home/ying/桌面/argv", load_options={'auto_load_libs': False})  # indirect_call aeon buffer_overflow overflow_recursive CFI
    print "cfg start!"
    cfg = b.analyses.CFGAccurate(keep_state=False, enable_symbolic_back_traversal=True)
    print "cfg end!"
    f = open('CFGnodes.txt', 'w')
    print >> f, cfg.nodes()
    f = open('CFGnodes.txt', 'r')
    line = f.read()
    nodes = line.split(',')
    s1 = []
    for node in nodes:
        s = re.findall('0x\w{5,20}', node)
        if s:
            s1.append(s[0])
    blocks = s1

    def findrip(block, count_cursion):
        count_cursion = count_cursion + 1
        irsb = b.factory.block(block).vex
        f = open('irsb.txt', 'w')
        print >> f, irsb.next
        f.close()
        f = open('irsb.txt', 'r')
        line = f.read()
        f.close()
        find0x = re.findall(r'(0x.*)', line)
        findt = re.findall(r'(t.*)', line)
        if find0x:
            if count_cursion > 100:
                print 'cursion too deep at block:', block
                return 0
            find0x1 = int(find0x[0], 16)
            findrip(find0x1, count_cursion)
        if findt:
            set0.add(hex(block))

    set0 = set([])
    angrMemoErr = []
    # set0 is a set, used to save blocks found
    print 'blocks of the binary:', blocks
    print 'looking for indirect-call blocks...'
    for block in blocks:
        count_cursion = 0
        try:
            findrip(int(block, 16), count_cursion)
        except angr.errors.AngrMemoryError:
            angrMemoErr.append(block)

    if (len(angrMemoErr) > 0):
        print 'angr.errors.AngrMemoryError: These blocks can be lib blocks:', angrMemoErr
    else:
        pass
    print 'found indirect-call blocks:', set0

    f = open('CFGedges.txt', 'w')
    print >> f, cfg.graph.edges()
    f = open('CFGedges.txt', 'r')
    line = f.read()
    edges = line.split(',')
    s1 = []
    for edge in edges:
        s = re.findall('0x\w{5,20}', edge)
        if s:
            s1.append(s[0])
    blocks = s1
    f = open('CFGedge_blocks.txt', 'w')
    print >> f, blocks
    f = open('CFGedge_jmp.txt', 'w')
    print >> f, set0
    print "looking for vulnerabilities....."
    set_b = []
    vulnerability = []
    err_block = []

    t1 = time.time()
    argv1 = claripy.BVS("argv1", 8 * 10)
    #y = claripy.BVS("y", 8 * 100)
    #z = claripy.BVS("z", 8 * 100)
    for test_block in set0:
        for i in range(len(blocks)):  # 将合法跳转地址存到set_b
            if (i % 2 == 0):
                if (blocks[i] == test_block):
                    set_b.append(blocks[i + 1])
                    #black_state.memory.store(0x20000, y)
                    #black_state.memory.store(0x30000, z)
        black_state = b.factory.entry_state(args=["clean-code",argv1],remove_options = {simuvex.o.LAZY_SOLVES})
        #black_state.memory.store(0x10000, x)
        p = b.factory.path(black_state)
        start_pg = b.factory.path_group(p)	#寻找指定block
        addr = int(test_block, 16)
        print "-" * 30
        #agl.block_addr.append(addr)
        agl.block_addr = [4195776, 4196608, 4195744, 4196026, 4195712, 4196058, 4195903, 4196018, 4196600, 4196527, 4195680, 4195792, 4196497, 4195981, 4196242, 4195760, 4196630, 4195992, 4195728, 4196120, 4196234, 4195669, 4195920, 4195696, 4195808]
        avoid_addr = [4196098, 4195776, 4196608, 4195744, 4196026, 4196904, 4196918, 4196788, 4195983, 4195824]
        if (addr in avoid_addr):
            continue
        # file_pc = open('constraints_callsites.txt','w+')
        # print "caller start!"
        # c = b.surveyors.Caller([0x1000, 0x2000,z], start=p)
        # print "explore start!"
        # print tuple(c.iter_returns())
        # print "-" * 30
        print 'block:',test_block
        start_pg.explore(find=addr, num_find=10)
        print "explore end!"
        #print 'block',test_block
        # print 'jump_address',set_b
        try:
            found = start_pg.found[3]
            pg = start_pg.found[3].state
            st_value = pg.se.any_n_str(argv1, 1)
            print st_value
        except IndexError:
            err_block.append(test_block)
            set_b=[]
            continue
        print "found step start!"
        found = start_pg.found[0]
        found.step()
        print "found step end!"
        print "-" * 30
        # found_new=found
        print "need_tmp_value!"
        print "agl.need_tmp_value:" , agl.need_tmp_value
        for tmp in agl.need_tmp_value:
            print "judging the type of temp value..."
            if tmp.concrete:
                print "concrete:", tmp
                print 'no crash at:', test_block  #
            else:
                print 'into slover:', test_block
                a = agl.now_state
                with open('constraints_callsites0.txt', 'w')as f:
                    f.write("len of pc:" + str(len(a.se.constraints)) + "\n" + str(a.se.constraints))
                # 从这里开始修改状态
                # a=agl.now_state
                print "add_constraints"
                print "len" + str(len(set_b)) + "\n" + str(tmp)
                # a.add_constraints(tmp==0x4005d7)
                # a.add_constraints(tmp!=0x4005c6)
                for j in range(len(set_b)):
                    a.add_constraints(tmp != int(set_b[j], 16))
                    with open('constraints_callsites1.txt', 'w')as f:
                        f.write("len of pc:" + str(len(a.se.constraints)) + "\n" + str(a.se.constraints))
                        if(a.se.satisfiable()==True):
                            print "satisfitable!"
                            vulnerability.append(hex(addr))
                            #x = a.memory.load(0x1000, 60)
                            x_value = a.se.any_n_str(argv1, 1)
                            print "x_value:", x_value
                            '''x_value_0 = x_value[0]
                            for xk in x_value_0:
                                print "hex:", hex(ord(xk))'''
                        else:
                            print "NO!"
        set_b = []  # set_b存放的是所有合法地址
        #agl.block_addr = []  # 每次循环完后初始化
        agl.need_tmp_value = []
    print 'agl.block_addr：',agl.block_addr
    print 'total time:', time.time() - t1, 's'
    if (len(err_block) > 0):
        print 'can not find:', err_block, 'with path_group'
    else:
        pass
    if (len(vulnerability) > 0):
        print 'Found CFI Vulnerabilities at:', vulnerability
    else:
        print 'No CFI Vulnerability found'
