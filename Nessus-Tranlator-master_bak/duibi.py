# coding: utf-8
# !/usr/bin/env python

from  nessusor import read_csv
reload(__import__('sys')).setdefaultencoding('utf-8')
import csv
import os, os.path
import sys
from lib.translator_excel import *
from lib.translator_txt import *
import argparse


def read_csv1(file_path):
    # 要转换的Nessus导出的csv文档
    with open(file_path, 'rb') as f:
        nessus = csv.reader(f)
        vules = [] # 风险级别，漏洞名， 端口, 描述，解决方案
        new_nessus = [] # 存放存在CVE漏洞编号且风险级别大于LOW的漏洞

        zz = [row for row in nessus] #判断是否为Nessus导出的csv
        check_csv = ['Plugin ID', 'CVE', 'CVSS', 'Risk', 'Host', 'Protocol', 'Port', 'Name', 'Synopsis', 'Description',\
                     'Solution', 'See Also', 'Plugin Output']
        if zz[0] != check_csv:
                print u'非Nessus导出结果文件'
                sys.exit()

        for row in zz:
            if row[3] in ['Critical', 'High', 'Medium','Low']:
                # 1cve 4host 7name 9description 10solution
                risk_name = row[3] + ',,' + row[6] + ',,' + row[7] + ',,' + row[4] # risk port name des solu
                vules.append(risk_name)
                new_nessus.append(row)
        # print list(set(vules))
        # 漏洞名称去重操作
        vul_names = list(set(vules))
        print len(vul_names)
        # print vul_names
        return vul_names,new_nessus
        # print len(vul_names)


vul_names,new_nessus=read_csv1('b.csv')
row_info = []
last_names,last_nessus=read_csv1('2018_quarter_2_outside_0ywbir.csv')
j=set(vul_names)&set(last_names)
for a in j:
	print a.split(',,')[3],a.split(',,')[1],a.split(',,')[0],a.split(',,')[2]
	row_info.append(list((a.split(',,')[3],a.split(',,')[1],a.split(',,')[0],a.split(',,')[2])))
print len(row_info)	
cols_name = [u'ip', u'port', u'risk', u'vul']
wbook = Workbook()
# print file_name.encode('utf-8')
wsheet = wbook.add_sheet('sheet')

# 设置excel的格式
col_style = easyxf('font: bold on; align: wrap on, vert centre, horiz center')#('font: name Times New Roman, color-index black, bold on')
row_style = easyxf('align: wrap on, vert centre, horiz center')
fnt = Font()
fnt.height = 2 * 20
style = XFStyle()
style.font = fnt	
r = 0
for line in row_info:
    print line
    # print u'遍历中文漏洞 ', line
    # print u'打印列数 ', len(cols_name)
    for c in xrange(len(cols_name)):

        if r == 0:
            try:
                wsheet.write(r, c, cols_name[c], col_style)
            except:
                pass
        elif c == 0:
            try:
                wsheet.write(r, c, line[c], row_style)
                wsheet.row(c).set_style(style)
                wsheet.col(c).width = 0x2400 + c
            except:
                pass
        elif c == 1:
            try:
                wsheet.write(r, c, line[c], row_style)
                wsheet.row(c).set_style(style)
                wsheet.col(c).width = 0x0fa0 + c
            except:
                pass
        elif c == 2:
            try:
                wsheet.write(r, c, line[c], row_style)
                wsheet.row(c).set_style(style)
                wsheet.col(c).width = 0x0fa0 + c
            except:
                pass
        elif c == 3:
            try:
                wsheet.write(r, c, line[c], row_style)
                wsheet.row(c).set_style(style)
                wsheet.col(c).width = 0x0fa0 + c
            except:
                pass	
    r += 1
wbook.save('bb'+'.xls')