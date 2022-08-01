#Lets make sure all "files" are covered
# Lets store it a DB
import pandas as pd
import sqlite3
from pprint import pprint
import dfxml.fiwalk as fiwalk
import dfxml 

import sys

imagefile = open("/home/oadegbeh/M57/pat-2009-12-10.raw.raw")
output_fh = open(sys.argv[1],'w+')
data = ""
def process(fi): # fi=fileobject
    #offset = fi.contents().find(data)
    #if offset>0:
    print(fi.filename())
    
objs = fiwalk.fileobjects_using_sax(imagefile=imagefile)
print(type(objs))
for i in range(1):
    print(objs[i].partition())

cols = ['obj_id', 'partition','inode','filename','filesize']
file_df = pd.DataFrame(columns=cols)


counter = 0
print(len(objs))
for obj in objs:
    if obj.is_file() == True and obj.filesize() > 1000000 :# and obj.filesize() == False:
        counter += 1
        byterun = []
        for ebyterun in obj.byte_runs():
            #print(ebyterun.img_offset,ebyterun.file_offset, ebyterun.len, ebyterun.fs_offset )
            if int(obj._tags['id']) > 6584: 
                pprint(vars(ebyterun)) 
                print(obj.filename(), "obj_id", obj._tags['id'], "partition",obj.partition(),"inode", obj.inode(),"filesize",  obj.filesize())
            byterun.append([ebyterun.img_offset,ebyterun.file_offset, ebyterun.len, ebyterun.fs_offset])
            #byterun.append([ebyterun.file_offset, ebyterun.len])
            #if hasattr(ebyterun,'img_offset'): byterun.append(ebyterun.img_offset)
            #if hasattr(ebyterun,'fs_offset'): byterun.append(ebyterun.fs_offset)
        #pprint(vars(ebyterun))
        #print( "inode:",obj.inode(), "partition:",obj.partition(), "name_type:",\
            #obj.name_type(),"id:",obj._tags['id'], "filename:",obj.filename(), "filesize:", obj.filesize() , \
                #"fragments", obj.fragments(), "img_offset:file_offset:len:fs_offset",byterun)
        data = [obj._tags['id'], obj.partition(),obj.inode(), obj.filename(),  obj.filesize()]
        print("data",data)
        output_fh.writelines(data)
        #file_df.loc[len(file_df.index)]= data
        #break
print(counter)
#print(len(file_df))