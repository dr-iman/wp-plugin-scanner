#!/usr/bin/python

#Wordpress Plugin Scanner By DeMoN ( Guardiran Security Team )
#insta:mr.faithful
#Site : Guardiran.org

#About Team :
#GuardIran security team is an independent group whose laws are not inconsistent
#with the policy of the Islamic Republic of Iran. GuardIran security team
#began its activity in 1393 and the team's goal of securing Iranian sites and servers.
#Our team is always ready to defend the frontiers of Iran's cyber our beloved land

#Usage Scan : python wp-plugin-scanner.py -t <UrlTarget>
#Get Help : python wp-plugin-scanner.py -h  

import argparse
import urllib2
import json
import re

line = "\n**************************************\n"
agent = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:50.0) Gecko/20100101 Firefox/50.0"
parser = argparse.ArgumentParser(description='WordPress Plugin Scanner')
parser.add_argument('-t' , '--target', help='The target url', required=True)
args = parser.parse_args()

def getVulnerabilities( pluginName ):
   	response = httpGet("https://wpvulndb.com/api/v1/plugins/" + pluginName)
   	
   	if response == None:
	   	return ' Not Vulnerable'
   	
   	results = json.loads(response)
   	msg = ''
   	
   	if results['plugin']:
   		if results['plugin']['vulnerabilities']:
   			vulnerabilitiesArray = results['plugin']['vulnerabilities']
   			for vul in vulnerabilitiesArray:
   				msg = msg + "\n" + vul['title']
   				
   	return msg

def httpGet( url ):
	try:
	   req = urllib2.Request(url)
	   req.add_unredirected_header('User-Agent', agent)
	   response = urllib2.urlopen(req)
	except urllib2.HTTPError, e:
		return None;
	return response.read()
 
if args.target is not None:
        print '''

 __      __                .___                                   
/  \    /  \___________  __| _/____________   ____   ______ ______
\   \/\/   /  _ \_  __ \/ __ |\____ \_  __ \_/ __ \ /  ___//  ___/
 \        (  <_> )  | \/ /_/ ||  |_> >  | \/\  ___/ \___ \ \___ \ 
  \__/\  / \____/|__|  \____ ||   __/|__|    \___  >____  >____  >
       \/                   \/|__|               \/     \/     \/ 
__________.__               .__                                   
\______   \  |  __ __  ____ |__| ____                             
 |     ___/  | |  |  \/ ___\|  |/    \                            
 |    |   |  |_|  |  / /_/  >  |   |  \                           
 |____|   |____/____/\___  /|__|___|  /                           
                    /_____/         \/                            
  _________                                                       
 /   _____/ ____ _____    ____   ____   ___________               
 \_____  \_/ ___\\__  \  /    \ /    \_/ __ \_  __ \              
 /        \  \___ / __ \|   |  \   |  \  ___/|  | \/              
/_______  /\___  >____  /___|  /___|  /\___  >__|                 
        \/     \/     \/     \/     \/     \/                     

 ==================================
 # Tools By : DeMoN               #
 # Team : Guardiran Security Team #
 # Site : Guardiran.org           #
 # insta:mr.faithful              #
 ==================================

'''
        print "Scanning...\n"
	
	html = httpGet(args.target)
	plugins = re.findall('\/wp-content\/plugins\/(.*?)\/', html, re.DOTALL)
	plugins = set(plugins)
	
	print line+" ......::: RESULT :::...... "+line
	
	pluginsCount = len(plugins)
	
	if pluginsCount == 0:
		print "No vulnerabilities were found.\n" + "Try checking manually.\n\n"+line
	else:
		print str(pluginsCount) + " plugins were detected"
		for plugin in plugins:
			vulnerabilities = getVulnerabilities(plugin)
			print line+"# "+plugin+line + vulnerabilities

	print line	
	
