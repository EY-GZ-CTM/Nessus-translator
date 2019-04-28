# coding: utf-8
# !/usr/bin/env python
reload(__import__('sys')).setdefaultencoding('utf-8')

import time
import csv
from baidu_traslate import *
from xlwt import *

def read_csv1(file_path):
    
    with open(file_path, 'rb') as f:
        nessus = csv.reader(f)
        vules = [] 
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

def csv_to_excel(vul_names, new_nessus, file_name= 'result'):
    # cur_names,cur_nessus=read_csv1('a.csv')
    
    # last_names,last_nessus=read_csv1('2018_quarter_2_inside_fmmszu.csv')    
    # jiaoji=set(cur_names)&set(last_names)
    # print jiaoji

    cols_name = [u'漏洞名称', u'影响主机', u'端口', u'协议',u'CVE编号', u'风险级别', u'修复方案',u'插件输出',u'原标题',u'是否新增']
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

    row_info = []
    for vul_name in vul_names:  # 遍历漏洞名
        host_list = []  # 影响主机列表，一个漏洞影响多个主机
        cve_list = []  # 漏洞的cve列表，一个漏洞对应多个CVE编号
        ports=[]
        protocol_list=[]
        Plugin_Output_list=[]
        host_ip_dict={}
        for new_vul in new_nessus:  # 提取每个漏洞对应的影响主机，提取对应的cve编号
            if new_vul[7] == vul_name.split(',,')[2]:
                print new_vul[4] , new_vul[6],new_vul[1]
                host_list.append(new_vul[4])
                cve_list.append(new_vul[1]+'')
                ports.append(new_vul[6])
                protocol_list.append(new_vul[5])
                if new_vul[4]+'-'+new_vul[6] not in host_ip_dict :
                    host_ip_dict[new_vul[4]+'-'+new_vul[6]]={}
                    host_ip_dict[new_vul[4]+'-'+new_vul[6]]['cve']=''
                    #host_ip_dict[new_vul[4]+'-'+new_vul[6]]['output']=''
                    host_ip_dict[new_vul[4]+'-'+new_vul[6]]['protocol']=new_vul[5]
                    # if new_vul[3] + ',,' + new_vul[6] + ',,' + new_vul[7] + ',,' + new_vul[4] in jiaoji:
                    #     host_ip_dict[new_vul[4]+'-'+new_vul[6]]['status']='N'
                    # else:
                    #     host_ip_dict[new_vul[4]+'-'+new_vul[6]]['status']='Y'

                Plugin_Output_list.append(new_vul[12])
                #print new_vul[12]
                host_ip_dict[new_vul[4]+'-'+new_vul[6]]['cve']=host_ip_dict[new_vul[4]+'-'+new_vul[6]]['cve']+'\n'+new_vul[1]
                #host_ip_dict[new_vul[4]+'-'+new_vul[6]]['output']=host_ip_dict[new_vul[4]+'-'+new_vul[6]]['output']+'\n'+new_vul[12]
        #print host_ip_dict
        print vul_name.split(',,')[2]
        name = vul_name.split(',,')[2]
        #hosts = '\n'.join(list(set(host_list)))
        #port = vul_name.split(',,')[1]
        #cves = '\n'.join(list(set(cve_list)))
        risk = vul_name.split(',,')[0]
        #Description = vul_name.split(',,')[3]#.replace('\n', ' ')
        Solution = vul_name.split(',,')[4]#.replace('\n', ' ')
        # tranlsate_info = name+'\t------------\t'+Description.replace('\n', ' ')+'\t------------\t'+Solution.replace('\n', ' ')
        # time.sleep(3)
        # cn_res = translate(tranlsate_info).split('------------')
        # print cn_res
        # print len(cn_res)
        # cn_name = cn_res[0]
        # cn_Description = cn_res[1]
        # cn_Solution = cn_res[2]
        # print tranlsate
        cn_name = translate(name)
        #print cn_name
        #time.sleep(3)
        #cn_Description = translate(Description.replace('\n',' '))
        #print cn_Description
        #time.sleep(3)
        cn_Solution = translate(Solution.replace('\n', ' '))
        #print cn_Solution
        print '--'*50
        # row_info.append(list((name, hosts, cves, risk, Description, Solution)))
        #row_info.append(list((cn_name, hosts, port, cves, risk, cn_Description, cn_Solution)))
        # for i in range(len(host_list)):
        #     print host_list[i], ports[i]
        #     row_info.append(list((cn_name, host_list[i], ports[i], protocol_list[i], cve_list[i], risk, cn_Solution,Plugin_Output_list[i],name)))
        for dictc in host_ip_dict:
            #print host_ip_dict[dictc]
            row_info.append(list((cn_name, dictc.split('-')[0], dictc.split('-')[1], host_ip_dict[dictc]['protocol'], host_ip_dict[dictc]['cve'], risk, cn_Solution,'',name)))
        print '--'*50

    #写入Excel操作
    if len(row_info) == 1:
        for row in row_info:
            for row_num in xrange(len(row_info) + 1):
                for col_num in xrange(len(cols_name)):
                        if row_num == 0:
                            try:
                                wsheet.write(row_num, col_num, cols_name[col_num], col_style)
                            except:
                                pass
                        else:
                            try:
                                wsheet.write(row_num, col_num, row[col_num], row_style)
                                wsheet.row(col_num).set_style(style)
                                wsheet.col(col_num).width = 0x2400 + col_num
                            except:
                                pass
    else:
        r = 0
        # print row_info[0][0]
        for line in row_info:
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
                elif c == 4:
                    try:
                        wsheet.write(r, c, line[c], row_style)
                        wsheet.row(c).set_style(style)
                        wsheet.col(c).width = 0x0fa0 + c
                    except:
                        pass
                elif c == 5:
                    try:
                        wsheet.write(r, c, line[c], row_style)
                        wsheet.row(c).set_style(style)
                        wsheet.col(c).width = 0x0fa0 + c
                    except:
                        pass
                elif c == 6:
                    try:
                        wsheet.write(r, c, line[c], row_style)
                        wsheet.row(c).set_style(style)
                        wsheet.col(c).width = 0x3c00 + c
                    except:
                        pass
                elif c == 7:
                    try:
                        wsheet.write(r, c, line[c], row_style)
                        wsheet.row(c).set_style(style)
                        wsheet.col(c).width = 0x3c00 + c
                    except:
                        pass  
                elif c == 8:
                    try:
                        wsheet.write(r, c, line[c], row_style)
                        wsheet.row(c).set_style(style)
                        wsheet.col(c).width = 0x3c00 + c
                    except:
                        pass        
                elif c == 9:
                    try:
                        wsheet.write(r, c, line[c], row_style)
                        wsheet.row(c).set_style(style)
                        wsheet.col(c).width = 0x3c00 + c
                    except:
                        pass                                                                    
            r += 1
    wbook.save(file_name+'.xls')
