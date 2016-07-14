#!/usr/bin/python
# -*- coding: utf-8 -*-

import inspect
import os
import traceback

# 0 ~ 102
str_type = ["00;30","01;30","02;30","04;30","07;30","09;30","00;31",\
            "01;31","02;31","04;31","07;31","09;31", \
            "00;32","01;32","02;32","04;32","07;32","09;32","00;33",\
            "01;33","02;33","04;33","07;33","09;33", \
            "00;34","01;34","02;34","04;34","07;34","09;34","00;35",\
            "01;35","02;35","04;35","07;35","09;35", \
            "00;36","01;36","02;36","04;36","07;36","09;36","00;37",\
            "01;37","02;37","04;37","07;37","09;37", \
            "00;40","01;40","02;40","04;40","07;40","09;40","00;90",\
            "00;41","01;41","02;41","04;41","07;41","09;41","00;91",\
            "00;42","01;42","02;42","04;42","07;42","09;42","00;92",\
            "00;43","01;43","02;43","04;43","07;43","09;43","00;93",\
            "00;44","01;44","02;44","04;44","07;44","09;44","00;94",\
            "00;45","01;45","02;45","04;45","07;45","09;45","00;95",\
            "00;46","01;46","02;46","04;46","07;46","09;46","00;96",\
            "00;47","01;47","02;47","04;47","07;47","09;47" ]


##############################################################################
# ColorLog
##############################################################################
class ColorLog():
    def __init__(self, a_log_flag=False):
        self.log_flag = a_log_flag

        callerframerecord = inspect.stack()[1]
        frame = callerframerecord[0]
        self.file = inspect.getframeinfo(frame).filename.split("/").pop()
        self.func = inspect.getframeinfo(frame).function
        self.line = inspect.getframeinfo(frame).lineno

    ##########################################################################
    # refresh log info
    ##########################################################################
    def get_line_num(self):
        callerframerecord = inspect.stack()[3]
        frame = callerframerecord[0]
        return inspect.getframeinfo(frame).lineno

    ##########################################################################
    # simple color log function : debug off
    ##########################################################################
    def printrs(self, prt):
        print("\033[91m{}\033[00m" .format(prt))

    def printgs(self, prt):
        print("\033[92m{}\033[00m" .format(prt))

    def printbs(self, prt):
        print("\033[94m{}\033[00m" .format(prt))

    def printys(self, prt):
        print("\033[93m{}\033[00m" .format(prt))

    ##########################################################################
    # detail color log fuction : debug on
    ##########################################################################
    def printrd(self, prt):
        print("\033[91m[%s:%d]{}\033[00m".format(prt) % (self.file, self.get_line_num()))

    def printgd(self, prt):
        print("\033[92m[%s:%d]{}\033[00m".format(prt) % (self.file, self.get_line_num()))

    def printbd(self, prt):
        print("\033[94m[%s:%d]{}\033[00m".format(prt) % (self.file, self.get_line_num()))

    def printyd(self, prt):
        print("\033[93m[%s:%d]{}\033[00m".format(prt) % (self.file, self.get_line_num()))

    ##########################################################################
    # color log fuction
    ##########################################################################
    def printr(self, prt):
        if self.log_flag is False:
            self.printrs(prt)
        else:
            self.printrd(prt)

    def printg(self, prt):
        if self.log_flag is False:
            self.printgs(prt)
        else:
            self.printgd(prt)

    def printb(self, prt):
        if self.log_flag is False:
            self.printbs(prt)
        else:
            self.printbd(prt)

    def printy(self, prt):
        if self.log_flag is False:
            self.printys(prt)
        else:
            self.printyd(prt)

    def printe(self):
        self.printrs("###################### traceback log ######################")
        print("\033[91m%s{}\033[00m" % self.get_traceback_str())


    def printu(self, type, prt):
        print("\x1b[" + str(type) + "m{}\x1b[00m".format(prt))

    def printt(self, type, prt):
        print("\x1b[" + str_type[type] + "m{}\x1b[00m".format(prt))

    def str_all_sample(self, ptr):
        for type_info in str_type:
            self.printu(type_info, str(str_type.index(type_info)) + ": " + ptr);

    ##########################################################################
    # error log stack trace
    ##########################################################################
    def get_traceback_str(self):
        lines = traceback.format_exc().strip().split('\n')

        rl = []
        lines = lines[0:-1]
        lines.reverse()
        nstr = ''

        for i in range(len(lines)):
            line = lines[i].strip()
            if line.startswith('File "'):
                eles = lines[i].strip().split('"')
                basename = os.path.basename(eles[1])
                lastdir = os.path.basename(os.path.dirname(eles[1]))
                eles[1] = '%s/%s' % (lastdir, basename)
                rl.append('%s %s' % (nstr, '"'.join(eles)))
                nstr = ''

        return '\n'.join(rl)

##############################################################################
# main
##############################################################################
if __name__ == "__main__":
    print "simple log test"
    log1 = ColorLog(False)
    log1.printr("color log function")
    log1.printg("color log function")
    log1.printb("color log function")
    log1.printy("color log function")

    print "detail log test"
    log2 = ColorLog(True)
    log2.printr("color log function")
    log2.printg("color log function")
    log2.printb("color log function")
    log2.printy("color log function")
    log2.printe()

    log2.str_all_sample("TEST")
    log2.printg("\n\n")
    log2.printt(98, "TEST")


