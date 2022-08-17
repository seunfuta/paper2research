# MPIpool.py

from mpi4py.futures import MPIPoolExecutor
import math
import textwrap
import hashlib
import os
import pandas as pd
from itertools import repeat
import sqlite3
import numpy as np
import pprint
from pprint import pprint
import dfxml 

def compute_hash(range_tuple):
    img_path = '/home/oadegbeh/M57/pat-2009-12-10.raw.raw'
    sector_hash_list = []
    print(range_tuple[0], range_tuple[1])
    sector_size = 512
    img_h = open(img_path, 'rb')
    for pointer in range(range_tuple[0], range_tuple[1]):
                #print(pointer)
                img_offset = pointer*sector_size
                img_h.seek(img_offset)
                fsector = img_h.read(sector_size)
                sector_md5 = hashlib.md5(fsector).hexdigest()
                sector_hash_list.append((img_offset,sector_md5))
    return sector_hash_list

def process_object_sectors(range_tuple):
    global options
    for obj in range(range_tuple[0], range_tuple[1]):
    
        # Filter out specific filenames create by TSK that are not of use
        if not obj.allocated():
            return
        print("processing %s" % str(obj))
        
        # See if the filename changed its hash code
        changed = False
        if not obj.allocated():
            return # only look at allocated files

        if int(obj._tags['id']) == id:# and obj.filesize() == False:
            #counter += 1
            #print(obj.filename())
            data = [obj._tags['id'], obj.partition(),obj.inode(), obj.filename(),  obj.filesize()]
            file_df.loc[len(file_df.index)] = data
            print(data)
            byterun = []
            persist_img_offset = 0
            persist_fs_offset = 0
            persist_file_offset = 0
            remaining_len = obj.filesize()
            ebyterun_df = pd.DataFrame(columns=['obj_id','img_offset','fs_offset','file_offset','len','md5','sha1'])
            for ebyterun in obj.byte_runs():
                #pprint(vars(ebyterun)) 
                #byterun.append([ebyterun.img_offset,ebyterun.file_offset, ebyterun.len, ebyterun.fs_offset])
                byterun.append(ebyterun.file_offset)
                persist_file_offset = ebyterun.file_offset
                byterun.append(ebyterun.len)
                if hasattr(ebyterun,'img_offset'): 
                    byterun.append(ebyterun.img_offset)
                    if ebyterun.img_offset != None: persist_img_offset = ebyterun.img_offset
                if hasattr(ebyterun,'fs_offset'): 
                    byterun.append(ebyterun.fs_offset)
                    if ebyterun.fs_offset != None: persist_fs_offset = ebyterun.fs_offset
                if hasattr(ebyterun,'len'): 
                    byterun.append(ebyterun.len)
                    if ebyterun.len != None: persist_len = ebyterun.len
                #print("img_offset", img_offset, "file offset", ebyterun.file_offset)
                #print("file_offset", "len", "img_offset", "fs_offset")
                byterun_start = int(persist_img_offset / sector_size)
                byterun_end = int((math.ceil((persist_img_offset + ebyterun.len) / sector_size))) - 1
                len_run = np.arange(persist_len,0,-sector_size) #remaining_len
                sector_run = np.full(len(len_run), sector_size)
                len_run = np.minimum(len_run,sector_run)
                #len_run = min(sector_size,len_run.all())
                print("len_run",len(len_run), len(len_run)*sector_size)
                print("byterun_start", byterun_start,persist_img_offset, "byterun_end", byterun_end,  "len", ebyterun.len)
                print("ebyterun_df", ebyterun_df.shape, "img_csv", img_csv_df.loc[byterun_start:byterun_end,'img_offset'].shape )
                #print(img_csv_df.loc[byterun_start:byterun_end,:])
                print("img_csv_len",len(img_csv_df.loc[byterun_start:byterun_end, :]))
                ebyterun_df.loc[:,'img_sector_offset'] = np.arange(len(img_csv_df))
                ebyterun_df.loc[byterun_start:byterun_end,'obj_id'] = obj._tags['id']
                ebyterun_df.loc[byterun_start:byterun_end,'img_offset'] = img_csv_df.loc[byterun_start:byterun_end,'img_offset']
                ebyterun_df.loc[byterun_start:byterun_end,'fs_offset'] = np.arange(persist_fs_offset,persist_fs_offset+ebyterun.len,sector_size)
                ebyterun_df.loc[byterun_start:byterun_end,'file_offset'] = np.arange(persist_file_offset,persist_file_offset+ebyterun.len, sector_size)
                ebyterun_df.loc[byterun_start:byterun_end,'len'] = len_run
                #print("remaining_len",remaining_len)
                #remaining_len-=sector_size
                ebyterun_df.loc[byterun_start:byterun_end,'md5'] = img_csv_df.loc[byterun_start:byterun_end,'md5']
            print(ebyterun_df)    

def determine_subranges(fullrange, num_subranges):
    """
    Break fullrange up into smaller sets of ranges that cover all
    the same numbers.
    """
    subranges = []
    inc = fullrange[1] // num_subranges
    for i in range(fullrange[0], fullrange[1], inc):
        subranges.append( (i, min(i+inc, fullrange[1])) )
    return( subranges )


if __name__ == '__main__':
    sector_size = 512
    img_path = '/home/oadegbeh/M57/pat-2009-12-10.raw.xml'
    object_number = dfxml.iter_dfxml(img_path, preserve_elements=True)
    img_objcount = len(list(object_number))
    fullrange = (0, img_objcount)
    num_subranges = 1000
    subranges = determine_subranges(fullrange, num_subranges)

    executor = MPIPoolExecutor()
    sectors_df_list = executor.map(process_object_sectors, subranges)
    files_df_list = executor.map(process_object_files, subranges)
    executor.shutdown()
    grand_sectors_df = pd.DataFrame()
    grand_files_df = pd.DataFrame()
    # flatten the list of lists
    for df in sectors_df_list:
        grand_sectors_df = pd.concat([grand_sectors_df, df])
    for df in files_df_list:
        grand_files_df = pd.concat([grand_files_df, df])
    #print(textwrap.fill(str(primes),80))
    con = sqlite3.connect("/scratch/oadegbeh/pat.db")
    grand_sectors_df.to_sql('block_hashes', con, index=True)
    grand_files_df.to_sql('files', con, index=True)
