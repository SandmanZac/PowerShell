#!/usr/bin/env python3
import os,csv

header = ['date-time','connector-id','session-id','sequence-number','local-endpoint','remote-endpoint','event','data','context']
'''
{'connector-id': 'DFEXHYBRID01\\Default Frontend DFEXHYBRID01',
 'context': 'Local',
 'data': '',
 'date-time': '2025-01-08T20:59:10.253Z',
 'event': '-',
 'local-endpoint': '10.15.5.173:25',
 'remote-endpoint': '10.15.5.173:45972',
 'sequence-number': '6',
 'session-id': '08DD2EE094B1BED6'}
'''

for filename in os.listdir('./'):
  if filename.lower().endswith('log'):
    with open(filename,'r') as file:
      csvFile = csv.reader(file)
      for line in csvFile:
        data = dict(zip(header,line))
        try:
          if '127.0.0' not in data['local-endpoint'] and '10.15.5.173' not in data['local-endpoint'] and '10.15.5.173' not in data['remote-endpoint'] and data['local-endpoint'] != 'local-endpoint':
            #print('Found one')
            print(data)
        except:
          #print(line)
          pass
    #os.sys.exit()
