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
from sklearn.metrics import confusion_matrix
from sklearn.metrics import accuracy_score
from sklearn.metrics import recall_score
from sklearn.metrics import precision_score
from sklearn.metrics import f1_score
from sklearn.metrics import classification_report
import argparse
SECTOR_SIZE = 512
SECTORS_PER_CLUSTER = 8

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
'''
parser = argparse.ArgumentParser(description='This is an image scanning program based on Jones\'s approach')
parser.add_argument('-i', action="store", dest="i", help='image (DB)', default='/Users/seunfuta/Downloads/NIST/DECAYED/3WSharks-decay25b.db') #image
parser.add_argument('-c', action="store", dest="c", help='catalog (DB)', default='/Users/seunfuta/Downloads/NIST/OluDB_combo_v3.db') #catalog
#parser.add_argument('-a', action="store", dest="a", help='application name  e.g. \
                #Wireshark-W7x64, Wireshark-W7x32, Winzip17pro-W7x32, Winzip17pro-W7x64,\
                #sdelete-W7x32, sdelete-W7x64, OfficePro2003-WinXP, OfficePro2003-W7x64,\
                #OfficePro2003-W7x32, Winrar5beta-W7x32, Firefox19-WinXP, Winrar5beta-W7x64,\
                #Firefox19-W7x32, HxD171-W7x32, Firefox19-W7x64, Thunderbird2-WinXP, \
                #Python264-WinXP, eraser-W7x32, Chrome28-W7x64, Chrome28-WinXP, Chrome28-W7x32,\
                #Safari157-W7x32, Safari157-WinXP, Safari157-W7x64, TrueCrypt63-WinXP, \
                #AdvancedKeylogger-WinXP, InvisibleSecrets21-WinXP, UPX-W7x32,UPX-W7x64', default='Wireshark-W7x64')
parser.add_argument('-o', action="store", dest="o", help='updated output image(DB)', default='/Users/seunfuta/Downloads/NIST/SCANNED/3WSharks-decay25b-Jscanned.db') #image
parser.add_argument('-ocsv', action="store", dest="ocsv", help='output result (CSV)', default='/Users/seunfuta/Downloads/NIST/SCANRESULT/3WSharks-decay25b-Jscanned.csv') #image
'''

'''wireshark, winzip, sdelete, office, winrar, 
firefox, chrome, safari, hxd, thunderbird, 
python, eraser, truecrypt, advancedkeylogger, 
invisiblesecrets, upx ') #app
'''

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
'''
def get_hashfreq_dict(catalog_path):
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

    hashfreq_dict = {}

    return hashfreq_dict
'''
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
    start = time()
    jones_df = pd.DataFrame()
        #columns=['Appname', 'tn', 'fp', 'fn', 'tp', 'accuracy', 'recall_0', 'recall_1', 'precision_0', 'precision_1',
                 #'f1_0', 'f1_1', 'image_size'])
    '''
    os_df = pd.read_csv("/Users/seunfuta/Downloads/NIST/NISToscatalog.csv")
    os_df.rename(columns={'md5': 'block_hash'}, inplace=True)
    os_uniqhash_df = pd.DataFrame(os_df.block_hash.value_counts()).reset_index()
    os_uniqhash_df.columns = ['block_hash', 'freq']
    '''
    resultc="/Users/seunfuta/Downloads/NIST/OluDB_combo_v3.db"
    resulti=sys.argv[1] #"/Users/seunfuta/Downloads/NIST/IMG/Wireshark-W7x64.db"
    resulto="/Users/seunfuta/Downloads/NIST/JONESSCAN/"
    #for app_number in range(0, len(diskprint_dict)):
    imgdf = pd.DataFrame()
    # input  = sys.argv[1]
    #key_list = app2diskprint_dict.app.unique() #app2diskprint_dict[result.a]
    result_df = pd.DataFrame(columns=['appname','appsize', 'actual','matches','P(app)'])

    imgdf = get_image_df(resulti)
    #### new
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

    catalog_sqlconn.close()
    key_list = catalog_df.app.unique()

    app_list = catalog_df.app.unique()
    global_md5_series = pd.Series()
    for each_app in app_list:
        appdf = catalog_df[catalog_df.app == each_app]
        each_apphash_list = appdf.md5.unique()
        global_md5_series = global_md5_series.append(pd.Series(each_apphash_list), ignore_index=True)
    global_md5_series_freq_map = global_md5_series.value_counts()
    
    key_list = list(key_list)

    for key in key_list:
        #key = 'Wireshark-W7x64'
        appdf = get_app_df(resultc, key)
        result_df.loc[key_list.index(key), 'appname'] = key
        print("appname",key)
        result_df.loc[key_list.index(key),'appsize'] = len(appdf)
        print("appsize",len(appdf))
        imgdf = imgdf.loc[:, ~imgdf.columns.duplicated()] #this removes duplicate columns ref https://stackoverflow.com/questions/14984119/python-pandas-remove-duplicate-columns
        # next step is to label the imgdf with the actual-app

        # get the short list of obj_id (that belongs to the app you are testing) in the
        app_file_filenames = appdf.filename.unique()  # type np.ndarray
        if str('actual-' + key) not in imgdf.columns:
            imgdf["actual-" + key] = np.where(imgdf.filename.isin(app_file_filenames), 1, 0)
        #print(imgdf["actual-" + diskprint_dict[key]].value_counts())

        #### get all unique block_hashes
        app_uniquemd5s = appdf.md5.unique()
        imgdf["predict-" + key] = np.where(imgdf.md5.isin(app_uniquemd5s), 1, 0)
        if 'decay' in imgdf.columns:
            imgdf.loc[imgdf.decay == 1,"predict-" + key] = 0 #if decay is set, your prediction should be null, didn't work
            imgdf.loc[imgdf.decay == 1, "actual-" + key] = 0
        else:
            imgdf = imgdf.assign(decay = 0)
        
        imgdf['freq'] = imgdf.md5.map(global_md5_series_freq_map)
        imgdf['inv_freq'] = 1/imgdf['freq']
        ###added
        imgdf['inv_freq'] = imgdf['inv_freq'].multiply(imgdf["predict-" + key], fill_value=0)
        ###end added
        result_df.loc[key_list.index(key), 'actual_uniq'] = len(imgdf[imgdf["actual-" + key]==1].drop_duplicates(subset='md5', keep='first'))
        print("actual_uniq", result_df.loc[key_list.index(key), 'actual_uniq'])

        result_df.loc[key_list.index(key), 'matches_uniq'] = len(imgdf[imgdf["predict-" + key]==1].drop_duplicates(subset='md5', keep='first'))
        print("matches_uniq", result_df.loc[key_list.index(key), 'matches_uniq'])

        result_df.loc[key_list.index(key), 'freq_matches_uniq'] = imgdf.drop_duplicates(subset='md5', keep='first')['inv_freq'].sum()
        print("freq_matches_uniq",result_df.loc[key_list.index(key), 'freq_matches_uniq'])

        result_df.loc[key_list.index(key),'appsize_uniq'] = len(appdf.drop_duplicates(subset='md5', keep='first'))
        print("appsize",len(appdf))
        print("appsize_uniq",result_df.loc[key_list.index(key),'appsize_uniq'])

        result_df.loc[key_list.index(key), 'P(app)new_uniq'] = round(float(result_df.loc[key_list.index(key), 'freq_matches_uniq'])/float(result_df.loc[key_list.index(key), 'appsize']),5)
        print("P(app)new_uniq", result_df.loc[key_list.index(key), 'P(app)new_uniq'])
    print(result_df)
    output_path = resulto+str(resulti.split("/")[-1][:-3])+".csv"
    result_df.to_csv(output_path, index=False)



