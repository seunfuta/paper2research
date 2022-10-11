# usage: python3 jones_scan_match_2.py /Volumes/Samsung_T5/Research/JSON/LastProj/ /Volumes/Samsung_T5/Research/IMGCSV/512-Python264-WinXP-BIOC.csv
# import fiwalk
import time
import os
import sys
import warnings
warnings.filterwarnings('ignore')
#sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
# import dfxml
import json
import argparse
import ast
import pandas as pd
import numpy as np
from timeit import default_timer as timer
import math
import sqlite3
# pd.set_option('display.max_colwidth', None)
from time import process_time
from time import time, strftime, localtime
from datetime import timedelta
# pd.set_option('display.max_columns', None)
from os import listdir
from os.path import isfile, join
import argparse

SECTOR_SIZE = 512
SECTORS_PER_CLUSTER = 8

#result = parser.parse_args()

def get_image_df(image_path):
    img_filepath = image_path
    img_sqlconn = sqlite3.connect(img_filepath)
    img_sectors_df = pd.DataFrame()
    img_sectors_df = pd.DataFrame(columns=['obj_id','file_offset','len','md5','sha1' ,'partition','inode','filename','filesize'])
    img_sectors_df = pd.read_sql_query("SELECT * FROM files INNER JOIN block_hashes ON files.obj_id = block_hashes.obj_id;", img_sqlconn)
    #block_hashes[obj_id,file_offset,len,md5,sha1,*decay], files[partition,inode,filename,filesize,*actual-APP]
    img_sectors_df = img_sectors_df[img_sectors_df.md5 != 'bf619eac0cdf3f68d496ea9344137e8b']
    img_sectors_df = img_sectors_df[img_sectors_df.md5 != 'de03fe65a6765caa8c91343acc62cffc']
    img_sectors_df = img_sectors_df[img_sectors_df.md5 != '85eba416ce0ee0951d1d93e73b191b75']
    img_sectors_df = img_sectors_df[img_sectors_df.md5 != '1b5c2cbf1e37f6b0d33751269ae707af']
    img_sqlconn.close()
    print("image length, ", len(img_sectors_df))
    return img_sectors_df

def get_app_df(catalog_path, key):
    catalog_filepath = catalog_path
    catalog_sqlconn = sqlite3.connect(catalog_filepath)
    appdf = pd.DataFrame(columns=['md5', 'file_offset', 'obj_id', 'filename', 'filesize'])
    appdf = pd.read_sql_query("SELECT block_hashes.md5, block_hashes.file_offset, files.obj_id, files.filename, files.filesize \
                FROM files \
                INNER JOIN block_hashes ON files.obj_id = block_hashes.obj_id \
                and files.inode = block_hashes.inode and files.app is '" + key + "';", catalog_sqlconn)
    appdf = appdf[appdf.md5 != 'bf619eac0cdf3f68d496ea9344137e8b']
    appdf = appdf[appdf.md5 != 'de03fe65a6765caa8c91343acc62cffc']
    appdf = appdf[appdf.md5 != '85eba416ce0ee0951d1d93e73b191b75']
    appdf = appdf[appdf.md5 != '1b5c2cbf1e37f6b0d33751269ae707af']

    catalog_sqlconn.close()
    print("catalog app length, ", len(appdf))
    return appdf

def get_key_list(catalog_path):
    catalog_filepath = catalog_path
    catalog_sqlconn = sqlite3.connect(catalog_filepath)
    appdf = pd.DataFrame(columns=['md5', 'file_offset', 'obj_id', 'filename', 'filesize'])
    key_list_df = pd.read_sql_query("SELECT DISTINCT app FROM files;", catalog_sqlconn)
    #appdf = appdf[appdf.md5 != 'bf619eac0cdf3f68d496ea9344137e8b']
    #appdf = appdf[appdf.md5 != 'de03fe65a6765caa8c91343acc62cffc']
    #catalog_sqlconn.close()
    #print("catalog app length, ", len(appdf))
    return key_list_df['app'].to_list()

if __name__ == "__main__":
    start = timer()
    jones_df = pd.DataFrame()
        #columns=['Appname', 'tn', 'fp', 'fn', 'tp', 'accuracy', 'recall_0', 'recall_1', 'precision_0', 'precision_1',
                 #'f1_0', 'f1_1', 'image_size'])

    resultc="/Users/seunfuta/Downloads/NIST/OluDB_combo_v3.db"
    resulti= "/Volumes/Samsung_T5/M57/pat2.db" #"/Users/seunfuta/Downloads/NIST/IMG/Wireshark-W7x64.db"
    resulto="/Volumes/Samsung_T5/M57/" #sys.argv[2]
    #for app_number in range(0, len(diskprint_dict)):
    imgdf = pd.DataFrame()
    # input  = sys.argv[1]
    #key_list = app2diskprint_dict.app.unique() #app2diskprint_dict[result.a]
    result_df = pd.DataFrame(columns=['appname','appsize', 'uniqappsize','matches_uniq', 'matches_f_sum', 'filecount', 'Prob'])#, 'actual','matches','P(app)'])

    imgdf = get_image_df(resulti)
    end_getimg = timer()
    print("after getting imgdf", int(end_getimg - start()))
    img_uniq_sectors_series = imgdf.md5.unique()
    print("unique image sectors", img_uniq_sectors_series)
    #hash_freq_dict = get_hashfreq_dict(result.c)
    catalog_filepath = resultc
    catalog_sqlconn = sqlite3.connect(catalog_filepath)
    catalog_df = pd.DataFrame(columns=['obj_id', 'inode', 'filename','file_offset', 'len','md5','sha1', 'partition', 'filesize','app','app_id'])
    catalog_df = pd.read_sql_query("SELECT block_hashes.obj_id, block_hashes.inode, block_hashes.filename, block_hashes.file_offset, \
                    block_hashes.len, block_hashes.md5, block_hashes.sha1, files.partition,files.filesize , files.app, files.app_id\
                    FROM files \
                    INNER JOIN block_hashes ON files.obj_id = block_hashes.obj_id \
                    and files.inode = block_hashes.inode and files.filename=block_hashes.filename;", catalog_sqlconn)
    print("original length ",len(catalog_df))
    catalog_df = catalog_df[catalog_df.md5 != 'bf619eac0cdf3f68d496ea9344137e8b']
    catalog_df = catalog_df[catalog_df.md5 != 'de03fe65a6765caa8c91343acc62cffc']
    catalog_df = catalog_df[catalog_df.md5 != '85eba416ce0ee0951d1d93e73b191b75']
    catalog_df = catalog_df[catalog_df.md5 != '1b5c2cbf1e37f6b0d33751269ae707af']
    #
    catalog_sqlconn.close()
    end_getcat = timer()
    print("after getting catdf", int(end_getcat - end_getimg))
    key_list = catalog_df.app.unique()
    '''
    app_list = catalog_df.app.unique()
    global_md5_series = pd.Series()
    for each_app in app_list:
        appdf = catalog_df[catalog_df.app == each_app]
        each_apphash_list = appdf.md5.unique()
        global_md5_series = global_md5_series.append(pd.Series(each_apphash_list), ignore_index=True)
    global_md5_series_freq_map = global_md5_series.value_counts()
    '''
    key_list = list(key_list)

    for appname in key_list[0:1]:
        appdf = catalog_df[catalog_df.app == appname]
        appfiles = list(appdf.filename.unique())
        appfiles_count = len(appfiles)
        app_fraction_df = pd.DataFrame(columns=['app','filename','match_f'])
        uniqueappsector_count = 0
        appsectormatches_uniqimg = 0
        file_match_fraction_total = float(0)
        file_counter = 0
        end_getcounter = timer()
        carried_timer = end_getcounter
        print("start of file counter", int(end_getcounter - end_getcat))
        for file in appfiles:
            print("#",file_counter, " out of ",  appfiles_count, file, len(appdf[appdf.filename == file]), "sectors")
            app_fraction_df.loc[appfiles.index(file),'app'] = appname
            app_fraction_df.loc[appfiles.index(file),'filename'] = file
            filedf = appdf[appdf.filename == file]
            file_uniqsectors = filedf.md5.unique()
            file_uniqsectors_count = len(file_uniqsectors)
            uniqueappsector_count += file_uniqsectors_count
            sector_matches_in_img = np.where(np.isin(img_uniq_sectors_series,file_uniqsectors),1,0)
            count_filesectormatches_uniqimg = sector_matches_in_img.sum()
            appsectormatches_uniqimg += count_filesectormatches_uniqimg
            file_match_fraction = round(float(count_filesectormatches_uniqimg)/float(file_uniqsectors_count), 4)
            file_match_fraction_total += file_match_fraction
            app_fraction_df.loc[appfiles.index(file), 'match_f'] = file_match_fraction
            end_filescan = timer()
            print("file scan time", end_filescan - carried_timer)
            carried_timer = end_filescan
            file_counter += 1
        app_prob = app_fraction_df.match_f.sum()    
        #result_df = pd.DataFrame(columns=['appname','appsize', 'uniqappsize','matches_uniq', 'matches_f_sum', 'filecount', 'Prob'])
        result_df.loc[key_list.index(appname), 'appname'] = appname
        result_df.loc[key_list.index(appname),'appsize'] = len(appdf)
        result_df.loc[key_list.index(appname),'uniqappsize'] = uniqueappsector_count
        result_df.loc[key_list.index(appname),'matches_uniq'] = appsectormatches_uniqimg
        result_df.loc[key_list.index(appname),'matches_f_sum'] = file_match_fraction_total
        result_df.loc[key_list.index(appname), 'filecount'] = appfiles_count
        result_df.loc[key_list.index(appname), 'Prob'] = round(float(file_match_fraction_total)/float(appfiles_count),4)
        result_df.loc[key_list.index(appname), 'Prob2'] = app_prob
    print(result_df)
    output_path = resulto+str(resulti.split("/")[-1][:-3])+".csv"
    result_df.to_csv(output_path, index=False)
    last_end = timer()
    print("total time", last_end - start)
