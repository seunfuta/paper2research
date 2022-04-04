# usage: python3 jones_scan_match_2.py /Volumes/Samsung_T5/Research/JSON/LastProj/ /Volumes/Samsung_T5/Research/IMGCSV/512-Python264-WinXP-BIOC.csv
# import fiwalk
import time
import os
import sys
import multiprocessing
#sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
# import dfxml
# import json
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
from sklearn.metrics import confusion_matrix
from sklearn.metrics import accuracy_score
from sklearn.metrics import recall_score
from sklearn.metrics import precision_score
from sklearn.metrics import f1_score
from sklearn.metrics import classification_report
import warnings
from itertools import repeat
from functools import reduce
warnings.filterwarnings('ignore')
diskprint_dict = {
        '9480-2-14416-1': 'Wireshark-W7x64',
        '9480-1-14417-1': 'Wireshark-W7x32',
        '9480-1-14782-1': 'Winzip17pro-W7x32',
        '9480-2-14782-1': 'Winzip17pro-W7x64',
        '9480-1-15142-1': 'sdelete-W7x32',
        '9480-2-15142-1': 'sdelete-W7x64',
        '234-1-14351-1': 'OfficePro2003-WinXP',
        '9480-2-14351-1': 'OfficePro2003-W7x64',
        '9480-1-14351-1': 'OfficePro2003-W7x32',
        '9480-1-15149-1': 'Winrar5beta-W7x32',
        '234-1-14887-1': 'Firefox19-WinXP',
        '9480-2-15149-1': 'Winrar5beta-W7x64',
        '9480-1-14887-1': 'Firefox19-W7x32',
        '9480-1-15150-1': 'HxD171-W7x32',
        '9480-2-14887-1': 'Firefox19-W7x64',
        '234-1-7959-1': 'Thunderbird2-WinXP',
        '234-1-15487-1': 'Python264-WinXP',
        '9480-1-15146-1': 'eraser-W7x32',
        '9480-2-15137-1': 'Chrome28-W7x64',
        '234-1-15137-1': 'Chrome28-WinXP',
        '9480-1-15137-1': 'Chrome28-W7x32',
        '9480-1-15151-1': 'Safari157-W7x32',
        '234-1-15151-1': 'Safari157-WinXP',
        '9480-2-15151-1': 'Safari157-W7x64',
        '234-1-15488-1': 'TrueCrypt63-WinXP',
        '234-1-15485-1': 'AdvancedKeylogger-WinXP',
        '234-1-15489-1': 'InvisibleSecrets21-WinXP',
        '9480-1-15141-1': 'UPX-W7x32',
        '9480-2-15141-1': 'UPX-W7x64'
}

app2diskprint_dict = {
    'Wireshark-W7x64': '9480-2-14416-1',
    'Wireshark-W7x32': '9480-1-14417-1',
    'Winzip17pro-W7x32': '9480-1-14782-1',
    'Winzip17pro-W7x64': '9480-2-14782-1',
    'sdelete-W7x32': '9480-1-15142-1',
    'sdelete-W7x64': '9480-2-15142-1',
    'OfficePro2003-WinXP': '234-1-14351-1',
    'OfficePro2003-W7x64': '9480-2-14351-1',
    'OfficePro2003-W7x32': '9480-1-14351-1',
    'Winrar5beta-W7x32': '9480-1-15149-1',
    'Firefox19-WinXP': '234-1-14887-1',
    'Winrar5beta-W7x64': '9480-2-15149-1',
    'Firefox19-W7x32': '9480-1-14887-1',
    'HxD171-W7x32': '9480-1-15150-1',
    'Firefox19-W7x64': '9480-2-14887-1',
    'Thunderbird2-WinXP': '234-1-7959-1',
    'Python264-WinXP': '234-1-15487-1',
    'eraser-W7x32': '9480-1-15146-1',
    'Chrome28-W7x64': '9480-2-15137-1',
    'Chrome28-WinXP': '234-1-15137-1',
    'Chrome28-W7x32': '9480-1-15137-1',
    'Safari157-W7x32': '9480-1-15151-1',
    'Safari157-WinXP': '234-1-15151-1',
    'Safari157-W7x64': '9480-2-15151-1',
    'TrueCrypt63-WinXP': '234-1-15488-1',
    'AdvancedKeylogger-WinXP': '234-1-15485-1',
    'InvisibleSecrets21-WinXP': '234-1-15489-1',
    'UPX-W7x32': '9480-1-15141-1',
    'UPX-W7x64': '9480-2-15141-1'
}

diskeyword_dict = {
    '9480-2-14416-1': ['wireshark'],
    '9480-1-14417-1': ['wireshark'],
    '9480-1-14782-1': ['winzip'],
    '9480-2-14782-1': ['winzip'],
    '9480-1-15142-1': ['sdelete'],
    '9480-2-15142-1': ['sdelete'],
    '234-1-14351-1': ['office', 'microsoft shared'],
    '9480-2-14351-1': ['office', 'microsoft shared'],
    '9480-1-14351-1': ['office', 'microsoft shared'],
    '9480-1-15149-1': ['winrar'],
    '234-1-14887-1': ['firefox', 'mozilla'],
    '9480-2-15149-1': ['winrar'],
    '9480-1-14887-1': ['firefox', 'mozilla'],
    '9480-1-15150-1': ['hxd'],
    '9480-2-14887-1': ['firefox', 'mozilla'],
    '234-1-7959-1': ['thunderbird'],
    '234-1-15487-1': ['python'],
    '9480-1-15146-1': ['eraser'],
    '9480-2-15137-1': ['chrome', 'google'],
    '234-1-15137-1': ['chrome', 'google'],
    '9480-1-15137-1': ['chrome', 'google'],
    '9480-1-15151-1': ['safari'],
    '234-1-15151-1': ['safari'],
    '9480-2-15151-1': ['safari'],
    '234-1-15488-1': ['trueCrypt'],
    '234-1-15485-1': ['keylogger'],
    '234-1-15489-1': ['invisible secrets'],
    '9480-1-15141-1': ['upx'],
    '9480-2-15141-1': ['upx']
}

parser = argparse.ArgumentParser(description='This is an image scanning program based on Olu\'s approach')
parser.add_argument('-i', action="store", dest="i", help='image (DB)', default='/Users/seunfuta/Downloads/NIST/DECAYED/3WSharks-decay25b.db') #image
parser.add_argument('-c', action="store", dest="c", help='catalog (DB)', default='/Users/seunfuta/Downloads/NIST/OluDB_combo_v3.db') #catalog
parser.add_argument('-a', action="store", dest="a", help='application name  e.g. \
                Wireshark-W7x64, Wireshark-W7x32, Winzip17pro-W7x32, Winzip17pro-W7x64,\
                sdelete-W7x32, sdelete-W7x64, OfficePro2003-WinXP, OfficePro2003-W7x64,\
                OfficePro2003-W7x32, Winrar5beta-W7x32, Firefox19-WinXP, Winrar5beta-W7x64,\
                Firefox19-W7x32, HxD171-W7x32, Firefox19-W7x64, Thunderbird2-WinXP, \
                Python264-WinXP, eraser-W7x32, Chrome28-W7x64, Chrome28-WinXP, Chrome28-W7x32,\
                Safari157-W7x32, Safari157-WinXP, Safari157-W7x64, TrueCrypt63-WinXP, \
                AdvancedKeylogger-WinXP, InvisibleSecrets21-WinXP, UPX-W7x32,UPX-W7x64', default='Wireshark-W7x64')
parser.add_argument('-o', action="store", dest="o", help='updated output image(DB)', default='/Users/seunfuta/Downloads/NIST/SCANNED/3WSharks-decay25b-Oscanned.db') #image
parser.add_argument('-ocsv', action="store", dest="ocsv", help='output result (CSV)', default='/Users/seunfuta/Downloads/NIST/SCANRESULT/3WSharks-decay25b-Oscanned.csv') #image
'''wireshark, winzip, sdelete, office, winrar, 
firefox, chrome, safari, hxd, thunderbird, 
python, eraser, truecrypt, advancedkeylogger, 
invisiblesecrets, upx ') #app
'''

#result = parser.parse_args()

def scan_list_v_world(lst1,lst2):
    #print("appfile", len(lst1))
    #print("image",len(lst2))
    #lst2 = imgdf_md5
    lst1_pairs = list(map(lambda x, y: x + y, lst1[:-1], lst1[1:]))
    set1_pairs = set(lst1_pairs)
    lst2_pairs = list(map(lambda a, b: a + b, lst2[:-1], lst2[1:]))
    forward_list = list(map(lambda x: 1 if x in set1_pairs else 0, lst2_pairs))
    forward_list.extend([0])
    #return forward_list

    lst3_pairs = list(map(lambda x, y: x + y, lst1[1:], lst1[:-1]))
    set3_pairs = set(lst3_pairs)
    lst4_pairs = list(map(lambda a, b: a + b, lst2[1:], lst2[:-1]))
    backward_list = [0]
    backward_list.extend(list(map(lambda x: 1 if x in set3_pairs else 0, lst4_pairs)))
    #return backward_list
    #return_list = list(a^b for a,b in zip(forward_list,backward_list))
    #print("return_list", len(return_list))
    #return_list = (pd.Series(forward_list) | pd.Series(backward_list)).astype(int)

    return backward_list

    #lst1_pairs = list(map(lambda x, y: x + y, lst1[:-1], lst1[1:]))
    #set1_pairs = set(lst1_pairs)
    #lst2_pairs = list(map(lambda a, b: a + b, lst2[:-1], lst2[1:]))
    #forward_list = list(map(lambda x: 1 if x in set1_pairs else 0, lst2_pairs))
    #return forward_list
    #return ((pd.Series(forward_list)|pd.Series(backward_list)).astype(int))

def get_image_df(image_path):
    img_filepath = image_path
    img_sqlconn = sqlite3.connect(img_filepath)
    img_sectors_df = pd.DataFrame()
    img_sectors_df = pd.DataFrame(columns=['obj_id','file_offset','len','md5','sha1' ,'partition','inode','filename','filesize'])
    img_sectors_df = pd.read_sql_query("SELECT * \
                                        FROM files INNER JOIN block_hashes ON files.obj_id = block_hashes.obj_id;", img_sqlconn)
    #block_hashes[obj_id,file_offset,len,md5,sha1,*decay], files[partition,inode,filename,filesize,*actual-APP]
    img_sectors_df = img_sectors_df[img_sectors_df.md5 != 'bf619eac0cdf3f68d496ea9344137e8b']
    img_sectors_df = img_sectors_df[img_sectors_df.md5 != 'de03fe65a6765caa8c91343acc62cffc']
    img_sqlconn.close()
    print("image length, ", len(img_sectors_df))
    return img_sectors_df

def get_catalog_df(catalog_path,key):
    catalog_filepath = catalog_path
    catalog_sqlconn = sqlite3.connect(catalog_filepath)
    appdf = pd.DataFrame(columns=['md5', 'file_offset', 'obj_id', 'filename', 'filesize'])
    appdf = pd.read_sql_query("SELECT block_hashes.md5, block_hashes.file_offset, files.obj_id, files.filename, files.filesize \
                FROM files \
                INNER JOIN block_hashes ON files.obj_id = block_hashes.obj_id \
                and files.inode = block_hashes.inode and files.app_id is '" + key + "';", catalog_sqlconn)
    appdf = appdf[appdf.md5 != 'bf619eac0cdf3f68d496ea9344137e8b']
    appdf = appdf[appdf.md5 != 'de03fe65a6765caa8c91343acc62cffc']
    catalog_sqlconn.close()
    print("catalog app length, ", len(appdf))
    return appdf

def start_process():
    print('Starting,',multiprocessing.current_process().name)

def do_scan(obj_id):
    file_df = appdf.loc[appdf.obj_id == obj_id].copy()
    file_md5 = file_df.md5
    return pd.Series(scan_list_v_world(file_md5, imgdf_md5))

if __name__ == "__main__":
    start = time()
    olu_df = pd.DataFrame()
        #columns=['Appname', 'tn', 'fp', 'fn', 'tp', 'accuracy', 'recall', 'precision',
                 #'f1', 'image_size'])
    '''
    os_df = pd.read_csv("/Users/seunfuta/Downloads/NIST/NISToscatalog.csv")
    os_df.rename(columns={'md5': 'block_hash'}, inplace=True)
    os_uniqhash_df = pd.DataFrame(os_df.block_hash.value_counts()).reset_index()
    os_uniqhash_df.columns = ['block_hash', 'freq']
    '''
    imgdf = pd.DataFrame()
    # input  = sys.argv[1]
    app_name = list(app2diskprint_dict.keys())[int(sys.argv[1])]
    key = app2diskprint_dict[app_name]#[result.a]

    imgdf = get_image_df("/Users/seunfuta/Downloads/NIST/IMG/"+app_name+".db")#(result.i)
    #imgdf.to_csv("/Users/seunfuta/Downloads/NIST/aa_imgdf.csv")
    appdf = get_catalog_df("/Users/seunfuta/Downloads/NIST/OluDB_combo_v3.db", key)#(result.c)
    imgdf = imgdf.loc[:, ~imgdf.columns.duplicated()] #this removes duplicate columns ref https://stackoverflow.com/questions/14984119/python-pandas-remove-duplicate-columns
    # next step is to label the imgdf with the actual-app
    print("image length, ", len(imgdf))
    # get the short list of filenames (that belongs to the app you are testing) in the
    app_file_filenames = appdf.filename.unique()  # type np.ndarray
    if str('actual-' + diskprint_dict[key]) not in imgdf.columns:
        imgdf["actual-" + diskprint_dict[key]] = np.where(imgdf.filename.isin(app_file_filenames), 1, 0)

    app_uniquemd5s = appdf.md5.unique()
    cat_obj_ids = appdf.obj_id.unique()
    mini_merger = pd.DataFrame()

    # imgdf_nocat = PORTIONS OF IMGDF THAT ARE NOT IN CATALOG_APP_DF
    imgdf_nocat = imgdf.loc[~imgdf.md5.isin(appdf.md5.values)].copy()

    file_count = int(1)
    mega_merger = pd.DataFrame()
    cat_obj_ids_len = len(cat_obj_ids)
    #print("cat_obj_id's", cat_obj_ids_len)
    cat_obj_id_counter = 0
    pred = pd.Series()
    global imgdf_md5
    imgdf_md5 = imgdf.md5
    list_of_file_dfs = []
    for obj_id in cat_obj_ids:
        file_df = appdf.loc[appdf.obj_id == obj_id].copy()
        file_md5 = file_df.md5
        list_of_file_dfs.append(file_md5)
    #return pd.Series(scan_list_v_world(file_md5, imgdf_md5))
    # STEP 6: SCANNING TEST IMAGE TO FIND APP MATCHES & VALIDAT
    # FOR EACH APP FILE (IN CATALOG)
    pool_size = 24
    pool = multiprocessing.Pool(processes=pool_size)
    #pool_outputs = pool.map(scan_list_v_world,list_of_file_dfs)
    pool_outputs = pool.starmap(scan_list_v_world, zip(list_of_file_dfs, repeat(imgdf_md5)))
    pool.close()
    pool.join()
    print("len of pool_outputs",len(pool_outputs))
    for out in pool_outputs:
        print(type(out),len(out))
    pred = reduce((lambda x, y: (pd.Series(x) | pd.Series(y)).astype(int)), pool_outputs)
    #for out in pool_outputs:
        #print()
        #pred = (pred | out).astype(int)
    print(pred.value_counts())
    #pred = pred.astype(int)
    pred_df = pd.DataFrame(pred, columns=["predict-" + diskprint_dict[key]])
    #imgdf = imgdf[imgdf['md5'].notna()]
    imgdf.reset_index(drop=True, inplace=True)
    imgdf = pd.concat([imgdf,pred_df],axis=1)
    #imgdf["predict-" + diskprint_dict[key]].fillna(int(0), inplace=True)
    #imgdf.to_csv("/Users/seunfuta/Downloads/NIST/xx_imgdf.csv")
    #imgdf["predict-" + diskprint_dict[key]] = imgdf["predict-" + diskprint_dict[key]].astype(int)
    imgdf = imgdf[imgdf['md5'].notna()]
    #imgdf["predict-" + diskprint_dict[key]] = pd.to_numeric(imgdf["predict-" + diskprint_dict[key]])
    print(imgdf["predict-" + diskprint_dict[key]].value_counts())
    end = time()
    print("time lapse:",end-start)
    #imgdf.to_csv("/Users/seunfuta/Downloads/NIST/uu_imgdf.csv")