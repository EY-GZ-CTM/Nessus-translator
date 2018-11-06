#!/usr/bin/python
# -*- coding: UTF-8 -*-
# import csv


import pandas as pd
import numpy as np
import sys
import numpy as np
#合并升级的漏洞	
def dealmap(data,keyword):
	apachedict={}	
	apacheindexlist=[]
	tempindex=None
	tempipandport=''
	for index, row in data.iterrows():   # 获取每行的index、row
		
		if keyword in row['Vulnerability Title']: 
			
			if(tempipandport!=row['Asset IP Address']+'-'+str(row['Service Port'])):
				tempindex=index
				tempipandport=row['Asset IP Address']+'-'+str(row['Service Port'])
				apachedict[str(index)]={}
				apachedict[str(index)]['Vulnerability Title']=row['Vulnerability Title']
				apachedict[str(index)]['Vulnerability Solution']=row['Vulnerability Solution']
			else:

				apachedict[str(tempindex)]['Vulnerability Title']=apachedict[str(tempindex)]['Vulnerability Title']+'\n'+row['Vulnerability Title']
				apachedict[str(tempindex)]['Vulnerability Solution']=apachedict[str(tempindex)]['Vulnerability Solution']+'\n'+row['Vulnerability Solution']
				apacheindexlist.append(index)
	for key in apachedict:
		#print key
		
		data.loc[long(key),'Vulnerability Title ']=apachedict[key]['Vulnerability Title']
		data.loc[long(key),'Vulnerability Solution ']=apachedict[key]['Vulnerability Solution']
		data.loc[long(key),'Solution Method']='升级'
		data.loc[long(key),'mark']='进行过合并的项'
	data=data.drop(apacheindexlist)
	return data
#删除多余列
def delColumn(lc):
	try:
		del lc['Asset OS Name']
	except :
		print 'Asset OS Name '+ 'is not exist'
	try:	
		del lc['Asset OS Version']
	except :
		print 'Asset OS Version'+ 'is not exist'
	try:
		del lc['Exploit Count ']
	except :
		print 'Exploit Count '+ 'is not exist'
	try:	
		del lc['Vulnerability Age']
	except :
		print 'Vulnerability Age '+ 'is not exist'	
	try:
		del lc['Service Name']
	except :
		print 'Service Name '+ 'is not exist'		
	del lc['Vulnerability Description']
	del lc['Vulnerability Test Date']
	try:
		del lc['Vulnerability Test Result Code']
	except :
		print 'Vulnerability Test Result Code '+ 'is not exist'		
	del lc['Vulnerability Proof']
	del lc['Vulnerability Test Result Description']


def resetLevel(data):
	for index, row in data.iterrows():   # 获取每行的index、row
		
		if(data.ix[index,'Vulnerability Title '] is np.nan or data.ix[index,'Vulnerability Title '] =='nan'):
			
			data.loc[index,'Vulnerability Title ']=row['Vulnerability Title']
			data.loc[index,'Vulnerability Solution ']=row['Vulnerability Solution']
			data.loc[index,'mark']='需要翻译'
		if(row['Vulnerability Severity Level']==5):
			data.loc[index,'Vulnerability Severity Level']='Severe'
		else:
			data.loc[index,'Vulnerability Severity Level']='Critical'
	return data

if __name__ == "__main__":

	print "脚本名：", sys.argv[0]
	lc=pd.DataFrame(pd.read_csv(sys.argv[1],header=0))
	vultitle=pd.DataFrame(pd.read_excel('vul-title.xlsx',header=0))
	#print [column for column in lc]
	print "读取文件:1 "+ sys.argv[1]
	for i in range(2, len(sys.argv)-1):
	    lc=lc.append(pd.read_csv(sys.argv[i]),ignore_index=True)
	    print "读取文件:"+str(i)+ ' '+sys.argv[i]
	print '只取5,8,9,10等级的漏洞'
	lc=lc.loc[lc["Vulnerability Severity Level"] >4]
	lc=lc.loc[lc["Vulnerability Severity Level"] != 6]
	lc=lc.loc[lc["Vulnerability Severity Level"] != 7]
	lc=lc.drop_duplicates(subset=['Asset IP Address','Service Port','Vulnerability Title'])  
	lc = lc.sort_values(by=['Asset IP Address','Vulnerability Severity Level'], ascending=False)

	delColumn(lc)

	result=pd.merge(lc,vultitle,on='Vulnerability Title',how='left')
	result=resetLevel(result)


	print '将'+'Apache Tomcat'+'进行了合并'
	result = result.sort_values(by=['Asset IP Address','Service Port'], ascending=False)
	result=dealmap(result,'Apache Tomcat')
	print '将'+'Apache HTTPD'+'进行了合并'

	result = result.sort_values(by=['Asset IP Address','Service Port'], ascending=False)
	result=dealmap(result,'Apache HTTPD')
	print '将'+'OpenSSL'+'进行了合并'
	result = result.sort_values(by=['Asset IP Address','Service Port'], ascending=False)
	result=dealmap(result,'OpenSSL')
	print '将'+'HP System Management Homepage'+'进行了合并'
	result = result.sort_values(by=['Asset IP Address','Service Port'], ascending=False)
	result=dealmap(result,'HP System Management Homepage')
	
	del result['Vulnerability Solution']

	del result['Vulnerability Title']
	result.to_excel(sys.argv[-1]+'.xlsx',sheet_name="sheet",index=False,header=True)
	print '导出文件:'+sys.argv[-1]+'.xlsx'

