import numpy as np
import time
import sys
import datetime
import os
from scipy.sparse import csr_matrix
import re
import random
import hmac
import hmac
import random
import pickle
from Crypto.Cipher import AES
import json
import string
from web3 import Web3
import json
from web3.middleware import geth_poa_middleware


sys.setrecursionlimit(10000)
w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8540"))
# w3 = Web3(Web3.WebsocketProvider("ws://127.0.0.1:8650"))
w3.middleware_onion.inject(geth_poa_middleware, layer=0)
# print(w3.eth.blockNumber)




#读取kw-file关系
f_Kw_File_Use = open('/Users/chen/PycharmProjects/ICC_2020_forward secure_verifiable/Kw_File_Use.txt','rb')
Kw_File_Use=pickle.load(f_Kw_File_Use)

kw_list=[]
print(Kw_File_Use)
for kw in Kw_File_Use:
    kw_list.append(kw)


#读取file-kw关系
f_file_to_file = open('/Users/chen/PycharmProjects/ICC_2020_forward secure_verifiable/file_to_file.txt','rb')
file_to_file=pickle.load(f_file_to_file)
print('file to file',file_to_file)
####所有文件的ID列表
list_file_ID=[]
for file in file_to_file:
    list_file_ID.append(file)

#私钥

secret_key1=hmac.new(b'chen').digest()
secret_key2=hmac.new(b'ZHANG').digest()
model = AES.MODE_ECB
BLOCK_SIZE = 16 # Bytes
def Build_index(Kw_File_Use, file_to_file):
    model = AES.MODE_ECB
    #***********index***********
    client_store_index={}
    server_kw_index={}
    server_ptr_file_nextptr={}
    server_ptr_getfirstptr={}
    chain_verify_index={}
    w_file_addr={}
    file_file_addr={}
    timecost_onchain=datetime.datetime.now()
    timecost_server=datetime.datetime.now()
    starttime=timecost_onchain
    timecost_client=datetime.datetime.now()
    starttime_client = timecost_client
    start_time_server=timecost_server
    # timecost_dual=0
    ############################### kw index

    for kw in Kw_File_Use:
        start = datetime.datetime.now()
        ################################################################################################生成客户端索引
        start_file_id = Kw_File_Use[kw][len(Kw_File_Use[kw]) - 1]  # client存储的首文件id
        # 计算首文件地址
        str1 = kw + start_file_id
        st = str1.encode('utf-8')  # 连接的字符串
        addr = hmac.new(st)
        start_file_addr = addr.digest()  # client存储的首文件地址
        upt_times = 0  # 更新次数,server与blockchain相同
        search_or_not=0   #0没搜索过，1搜索过
        client_store_index[kw] = [upt_times, search_or_not, start_file_addr]
        # client生成token（server端文件地址+文件内容）
        # 字符串连接
        tok_server_addr = (kw + str(upt_times)).zfill(16)  # w||s
        # 转字节
        t_addr = tok_server_addr.encode('utf-8')
        # 加密生成token
        aes1 = AES.new(secret_key1, model)
        aes2 = AES.new(secret_key2, model)
        # 生成token
        tw1 = aes1.encrypt(t_addr)
        onchain_token = aes2.encrypt(t_addr)
        end = datetime.datetime.now()
        t=end-start
        timecost_client=timecost_client+t

        for i in range(len(Kw_File_Use[kw])):
            if i == 0:  # nonce块
                sser=datetime.datetime.now()
                ###############生成当前文件地址
                str1 = kw.encode('utf-8') + Kw_File_Use[kw][0]  # kw||nonce
                addr = hmac.new(str1)
                addr_file = addr.digest()  # w_nonce地址
                w_file_addr[kw] = [addr_file] #存储kw对应文件地址列表
                ################生成当前G
                # G1(tw1,ptr)
                aes_t1 = AES.new(tw1, model)  # token做key进行加密
                G_token_S_addr = aes_t1.encrypt(addr_file)
                #####异或下一文件地址，所有nonce块都异或b'NNNNNNNNNNNNNNNN'
                xor_addr = bytes(a ^ b for a, b in zip(G_token_S_addr, b'NNNNNNNNNNNNNNNN'))

                ####异或文件iD
                xor_fileid=bytes(a ^ b for a, b in zip(G_token_S_addr, Kw_File_Use[kw][0]))
                start1 = datetime.datetime.now()
                # 计算fileID的hash
                start1 = datetime.datetime.now()
                hfid = hmac.new(Kw_File_Use[kw][0])
                hashfid = hfid.digest()  # fid hash
                end1 = datetime.datetime.now()
                t1=end1-start1
                timecost_onchain = timecost_onchain + t1
                #####与nonce的hash值异或
                xor_hashid = bytes(a ^ b for a, b in zip(G_token_S_addr, hashfid))  # 与nonce直接异或
                server_kw_index[addr_file] = [xor_addr, xor_hashid, xor_fileid]  # server端nonce块的数据
                enser=datetime.datetime.now()
                timecost_server=timecost_server+(enser-sser)
                start2 = datetime.datetime.now()
                chain_verify_index[onchain_token] = hashfid
                end2 = datetime.datetime.now()
                t2=end2-start2
                timecost_onchain=timecost_onchain+t2
            else:
                # 获得地址
                sser = datetime.datetime.now()
                file_id = Kw_File_Use[kw][i]  # 对应文件名字
                str1 = kw + file_id  # 连接的字符串
                st = str1.encode('utf-8')  # 转字节
                addr = hmac.new(st)
                addr_file = addr.digest()  # 得到kw连接file地址
                w_file_addr[kw].append(addr_file)
                ################生成当前G
                # G1(tw1,ptr)
                aes_t1 = AES.new(tw1, model)  # token做key进行加密
                G_token_S_addr = aes_t1.encrypt(addr_file)
                #####异或下一文件地址，异或异或前一个块
                # 上一文件地址
                last_file_addr = w_file_addr[kw][i - 1]
                # 异或上一文件地址
                xor_addr = bytes(a ^ b for a, b in zip(G_token_S_addr, last_file_addr))
                # 获得文件ID的密文 Enc(k,fi)
                fid_byte=Kw_File_Use[kw][i].encode('utf-8')
                enc_file_ID = aes1.encrypt(fid_byte)
                # 计算fileID的hash
                start3 = datetime.datetime.now()
                hfid = hmac.new(enc_file_ID)
                hashfid = hfid.digest()  # fid hash
                end3 = datetime.datetime.now()
                t3 = end3 - start3
                timecost_onchain = timecost_onchain + t3
                timecost_server=timecost_server+(end3-sser)
                #####与file的hash值异或
                s=datetime.datetime.now()
                xor_hashid = bytes(a ^ b for a, b in zip(G_token_S_addr, hashfid))  # 与nonce直接异或
                ####异或加密的文件iD
                xor_fileid = bytes(a ^ b for a, b in zip(G_token_S_addr, enc_file_ID))
                server_kw_index[addr_file] = [xor_addr, xor_hashid, xor_fileid]  # server端nonce块的数据
                e=datetime.datetime.now()
                timecost_server = timecost_server + (e - s)
                start3 = datetime.datetime.now()
                chain_verify_index[onchain_token] = bytes(a ^ b for a, b in zip(chain_verify_index[onchain_token], hashfid))
                end3 = datetime.datetime.now()
                t3 = end3 - start3
                timecost_onchain = timecost_onchain + t3
    timecost_onchain=timecost_onchain-starttime
    timecost_client=timecost_client-starttime_client
    ############################### file index
    start=datetime.datetime.now()
    for file in file_to_file:

        # 计算文件hash,先加密
        fid_byte=file.encode('utf-8')
        enc_file_ID = aes1.encrypt(fid_byte)
        addr = hmac.new(enc_file_ID)
        # server存储文件hash（key）
        enc_file_hash = addr.digest()
        # 计算文件首地址（用最后一个当头）
        kw=file_to_file[file][len(file_to_file[file]) - 1]
        str2=kw+file
        st = str2.encode('utf-8')  # 连接的字符串
        file_addr = hmac.new(st)
        start_file_addr = file_addr.digest()
        #获得文件首地址index
        server_ptr_getfirstptr[enc_file_hash]=start_file_addr
        for i in range(len(file_to_file[file])):
            #第一个文件，异或下一地址NULL
            if i==0:
                #获得地址
                s = file_to_file[file][0] + file  # 连接的字符串
                st = s.encode('utf-8')  # 转字节
                addr = hmac.new(st)
                # 得到kw连接file地址
                addr_file = addr.digest()
                file_file_addr[file] = [addr_file]  # 存储file-file对应地址列表     #****************???
                # G(enfid,ptr)
                aes_t1 = AES.new(enc_file_ID, model)  # token做key进行加密
                G_file = aes_t1.encrypt(addr_file)
                #####异或下一文件地址b'NNNNNNNNNNNNNNNN'
                xor_addr_file = bytes(a ^ b for a, b in zip(G_file, b'NNNNNNNNNNNNNNNN'))
                server_ptr_file_nextptr[addr_file]=xor_addr_file
            else:
                str1 = file_to_file[file][i] + file  # 连接的字符串
                st = str1.encode('utf-8')  # 转字节
                addr = hmac.new(st)
                # 得到kw连接file地址
                addr_file = addr.digest()
                file_file_addr[file].append(addr_file)
                # G(fid,ptr)
                aes_t1 = AES.new(enc_file_ID, model)  # token做key进行加密
                G_file = aes_t1.encrypt(addr_file)
                last_file_addr=file_file_addr[file][i-1]
                xor_addr_file = bytes(a ^ b for a, b in zip(G_file, last_file_addr))
                server_ptr_file_nextptr[addr_file] = xor_addr_file
    end=datetime.datetime.now()
    timecost_server=timecost_server+(end-start)
    timecost_server=timecost_server-start_time_server
    return client_store_index, server_kw_index, server_ptr_file_nextptr, server_ptr_getfirstptr, chain_verify_index,timecost_onchain,timecost_client,timecost_server


def delete_file(delete_fileid,server_ptr_getfirstptr,server_kw_index,server_ptr_file_nextptr):

    # generate token(ID加密后的hash)
    aes1 = AES.new(secret_key1, model)
    fid_byte = delete_fileid.encode('utf-8')
    enc_file_ID = aes1.encrypt(fid_byte)
    addr = hmac.new(enc_file_ID)
    file_hash = addr.digest()
    firstptr=server_ptr_getfirstptr[file_hash]
    ###删除文件id
    server_kw_index[firstptr][2]='delete000'
    ####计算下一文件地址
    # G(encfid,ptr)
    aes_t1 = AES.new(enc_file_ID, model)  # token做key进行加密
    G_file = aes_t1.encrypt(firstptr)
    nextfile_ptr=bytes(a ^ b for a, b in zip(G_file, server_ptr_file_nextptr[firstptr]))
    i=1
    while nextfile_ptr!=b'NNNNNNNNNNNNNNNN':
        # i=i+1
        # if nextfile_ptr in server_kw_index:
        #     print('yes ')
        # else:
        #     print('no')
        # print('delete_fileid',delete_fileid)
        # print('nextfile_ptr',nextfile_ptr)
        # print(i)
        server_kw_index[nextfile_ptr][2] = 'delete000'
        G_file = aes_t1.encrypt(nextfile_ptr)
        nextfile_ptr = bytes(a ^ b for a, b in zip(G_file, server_ptr_file_nextptr[nextfile_ptr]))
    return server_kw_index



################添加文件
####添加文件，这里所有文件只有一个关键字
def add_file(addfile_kw, addfile_nonce, addfile_ID, client_store_index,server_kw_index,server_ptr_file_nextptr, server_ptr_getfirstptr, chain_verify_index,sum_time_server, sum_time_chain):
    upt_times, search_or_not, before_start_addr = client_store_index[addfile_kw]
    ###更新client index
    ##如果搜索过,s+1

    if search_or_not==1:
        upt_times=upt_times+1
        # client_store_index[addfile_kw][0]=client_store_index[addfile_kw][0]+1
    ##首地址（文件块）

    by_id = (addfile_kw+addfile_ID).encode('utf-8')
    addr = hmac.new(by_id)
    start_file_addr = addr.digest()  # client存储的首文件地址
    client_store_index[addfile_kw]=[upt_times, search_or_not, start_file_addr]
    time_server = datetime.datetime.now()
    time_chain = datetime.datetime.now()
    starttt = time_server
    ## client生成token（server端文件地址+文件内容）
    # 字符串连接
    start = datetime.datetime.now()
    tok_server_addr = (addfile_kw + str(upt_times)).zfill(16)  # w||s

    # 转字节
    t_addr = tok_server_addr.encode('utf-8')
    # 加密生成token
    end = datetime.datetime.now()
    time_chain = time_chain + (end - start)
    time_server=time_server+(end-start)

    start1 = datetime.datetime.now()
    aes2 = AES.new(secret_key2, model)
    onchain_token = aes2.encrypt(t_addr)
    end = datetime.datetime.now()
    time_chain = time_chain + (end - start1)
    # 生成token
    start = datetime.datetime.now()
    aes1 = AES.new(secret_key1, model)
    tw1 = aes1.encrypt(t_addr)
    end = datetime.datetime.now()
    time_server = time_server + (end - start)
    ##################先处理nonce块，其下一块地址为原来client中存储的
    # 生成nonce块地址
    start = datetime.datetime.now()
    s = addfile_kw.encode('utf-8') + addfile_nonce  # 连接的字符串
    addr = hmac.new(s)
    addr_file = addr.digest()  # w_nonce地址
    ##nonce块的地址是addfile的前一块
    last_file_addr=addr_file
    # G(fid,ptr)
    aes_t1 = AES.new(tw1, model)  # token做key进行加密
    G_token_S_addr = aes_t1.encrypt(addr_file)
    #####异或下一文件地址(原头文件)
    xor_addr = bytes(a ^ b for a, b in zip(G_token_S_addr, before_start_addr))
    # 计算nonce的hash
    hfid = hmac.new(addfile_nonce)
    hashfid = hfid.digest()
    st2 = datetime.datetime.now()

    #####与nonce的hash值异或
    xor_hashid = bytes(a ^ b for a, b in zip(G_token_S_addr, hashfid))  # 与nonce直接异或
    ed2=datetime.datetime.now()
    time_chain = time_chain + (ed2 - st2)
    ####异或文件iD
    xor_fileid = bytes(a ^ b for a, b in zip(G_token_S_addr, addfile_nonce))
    server_kw_index[addr_file] = [xor_addr, xor_hashid, xor_fileid]  # server端nonce块的数据
    end2 = datetime.datetime.now()
    time_server = time_server + (end2 - start)
    start=datetime.datetime.now()
    chain_verify_index[onchain_token] = bytes(a ^ b for a, b in zip(chain_verify_index[onchain_token], hashfid))
    end = datetime.datetime.now()
    time_chain = time_chain + (end - start)
    #########################处理文件块，下一块地址为nonce块地址##############################
    # 获得地址
    start=datetime.datetime.now()
    addr_file=start_file_addr
    ################生成当前G
    st2=datetime.datetime.now()
    aes_t1 = AES.new(tw1, model)  # token做key进行加密
    G_token_S_addr = aes_t1.encrypt(addr_file)
    en2=datetime.datetime.now()
    time_chain = time_chain + (en2 - st2)
    #####异或上一文件地址（nonce块）
    xor_addr = bytes(a ^ b for a, b in zip(G_token_S_addr, last_file_addr))
    # 获得文件ID的密文，先加密 Enc(k,fi)
    st2 = datetime.datetime.now()
    fid_byte = addfile_ID.encode('utf-8')
    enc_file_ID = aes1.encrypt(fid_byte)
    # 计算fileID的hash
    hfid = hmac.new(enc_file_ID)
    hashfid = hfid.digest()  # fid hash
    en2 = datetime.datetime.now()
    time_chain = time_chain + (en2 - st2)
    #####与file的hash值异或
    xor_hashid = bytes(a ^ b for a, b in zip(G_token_S_addr, hashfid))  # 与nonce直接异或
    ####异或加密的文件iD
    xor_fileid = bytes(a ^ b for a, b in zip(G_token_S_addr, enc_file_ID))
    server_kw_index[addr_file] = [xor_addr, xor_hashid, xor_fileid]  # server端nonce块的数据
    ###################处理文件索引
    ###生成文件首地址索引
    server_ptr_getfirstptr[hashfid] = start_file_addr
    xor_addr_file = bytes(a ^ b for a, b in zip(start_file_addr, b'NNNNNNNNNNNNNNNN'))
    server_ptr_file_nextptr[addr_file] = [xor_addr_file]
    end2 = datetime.datetime.now()
    time_server = time_server + (end2 - start)
    start = datetime.datetime.now()
    chain_verify_index[onchain_token] = bytes(a ^ b for a, b in zip(chain_verify_index[onchain_token], hashfid))
    end= datetime.datetime.now()
    time_chain=time_chain+(end-start)
    this_iteration_server_time=time_server-starttt
    this_iteration_chain_time=time_chain-starttt
    sum_time_server=sum_time_server+this_iteration_server_time
    sum_time_chain=sum_time_chain+this_iteration_chain_time
    return client_store_index, server_kw_index, server_ptr_file_nextptr, server_ptr_getfirstptr, chain_verify_index,sum_time_server,sum_time_chain

###################################################搜索
###################################################搜索

#确定要搜索的kw，生成发给server和blockchain的token
def owner_generate_search_token(client_store_index,inputKW):
    # inputKW=input("请输入要搜索的关键字")
    upt_times, search_or_not, start_file_addr=client_store_index[inputKW]
    # print('upt_times',upt_times)
    # print('search_or_not',search_or_not)
    tok=(inputKW+str(upt_times)).zfill(16)  # w||s
    t_wands = tok.encode('utf-8')
    aes1 = AES.new(secret_key1, model)
    aes2 = AES.new(secret_key2, model)
    search_server_token = aes1.encrypt(t_wands)
    search_onchain_token = aes2.encrypt(t_wands)
    # client_store_index[inputKW][search_or_not]=1
    #获得首地址
    return client_store_index, search_server_token, search_onchain_token,start_file_addr


def server_search(search_server_token,search_onchain_token, server_kw_index, start_file_addr, list_searchresult_hashfid, list_searchresult_fid):

    xor_addr, xor_hashid, xor_fileid=server_kw_index[start_file_addr]
    ################生成当前G
    # G1(tw1,ptr)

    aes_t1 = AES.new(search_server_token, model)  # token做key进行加密
    G_token_S_addr = aes_t1.encrypt(start_file_addr)
    # 获得下一文件地址
    next_file_addr = bytes(a ^ b for a, b in zip(G_token_S_addr, xor_addr))
    # 获得当前文件hash
    current_file_hash=bytes(a ^ b for a, b in zip(G_token_S_addr, xor_hashid))
    # 获得当前文件ID
    if xor_fileid!='delete000':
        current_file_id=bytes(a ^ b for a, b in zip(G_token_S_addr, xor_fileid))
        list_searchresult_fid.append(current_file_id)
    list_searchresult_hashfid.append(current_file_hash)
    if next_file_addr!=b'NNNNNNNNNNNNNNNN':
        return server_search(search_server_token,search_onchain_token, server_kw_index, next_file_addr, list_searchresult_hashfid, list_searchresult_fid)
    else:
        return list_searchresult_hashfid, list_searchresult_fid



abi_build_index=    """
[
	{
		"constant": false,
		"inputs": [
			{
				"name": "token",
				"type": "bytes16"
			}
		],
		"name": "try_whether_equal",
		"outputs": [
			{
				"name": "current_xor",
				"type": "int256"
			}
		],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "totalnumber",
				"type": "uint256"
			}
		],
		"name": "getlastxor",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "ctoken",
				"type": "bytes16"
			},
			{
				"name": "dhash",
				"type": "bytes16"
			}
		],
		"name": "set",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "enfile",
				"type": "bytes16[]"
			},
			{
				"name": "len",
				"type": "uint256"
			},
			{
				"name": "blocknum",
				"type": "uint256"
			}
		],
		"name": "batch_gethash",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [],
		"name": "check_equal_or_not",
		"outputs": [
			{
				"name": "",
				"type": "int256"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [],
		"name": "is_equal",
		"outputs": [
			{
				"name": "",
				"type": "int256"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "ctoken",
				"type": "bytes16[]"
			},
			{
				"name": "dhash",
				"type": "bytes16[]"
			},
			{
				"name": "len",
				"type": "uint256"
			}
		],
		"name": "setbatch",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "",
				"type": "bytes16"
			}
		],
		"name": "blockindex",
		"outputs": [
			{
				"name": "",
				"type": "bytes16"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [],
		"name": "finish_xor",
		"outputs": [
			{
				"name": "",
				"type": "bytes16"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "",
				"type": "uint256"
			}
		],
		"name": "blockxor",
		"outputs": [
			{
				"name": "",
				"type": "bytes16"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	}
]
"""

from_account = w3.toChecksumAddress("0x93fe512AB64FC39B103527464547869D2986Adc7")
abi_build_index = json.loads(abi_build_index)
store_var_contract = w3.eth.contract(
   address=w3.toChecksumAddress('0x9964495C9790F208F5F40882cab3f980C99523ae'),
   abi=abi_build_index)





def on_chain_search(list_searchresult_hashfid,search_onchain_token):
    ####################################对搜索结果   list_search2   分块
    batchfileint1 = int(len(list_searchresult_hashfid) / 2000)
    batchfileyue1 = len(list_searchresult_hashfid) % 2000
    # print("batchfileint1", batchfileint1)
    # print("batchfileyue1", batchfileyue1)
    # print(batchint1)
    # print(batchyue1)
    xor_each_result = []
    earchpart = 0
    onchain_verify_gascost = 0

    start = datetime.datetime.now()
    for i in range(0, len(list_searchresult_hashfid), 2000):
        if earchpart < batchfileint1:
            part = list_searchresult_hashfid[i:i + 2000]
            tx_hash5 = store_var_contract.functions.batch_gethash(part, len(part), earchpart).transact({
                "from": from_account,
                "gas": 90000000,
                "gasPrice": 0,
            })
            tx_receipt1 = w3.eth.waitForTransactionReceipt(tx_hash5)

            onchain_verify_gascost = onchain_verify_gascost + tx_receipt1.gasUsed
        else:
            part = list_searchresult_hashfid[i:i + batchfileyue1]
            # print("part", len(part))
            # print(earchpart)
            tx_hash6 = store_var_contract.functions.batch_gethash(part, len(part), earchpart).transact({
                "from": from_account,
                "gas": 90000000,
                "gasPrice": 0,
            })
            tx_receipt2 = w3.eth.waitForTransactionReceipt(tx_hash6)

            onchain_verify_gascost = onchain_verify_gascost + tx_receipt2.gasUsed
        earchpart = earchpart + 1

    # 将所有块的hash拼到一起
    tx_hash7 = store_var_contract.functions.getlastxor(batchfileint1).transact({"from": from_account,
                                                                                "gas": 3000000,
                                                                                "gasPrice": 0,
                                                                                })
    tx_receipt3 = w3.eth.waitForTransactionReceipt(tx_hash7)
    onchain_verify_gascost = onchain_verify_gascost + tx_receipt3.gasUsed
    #######
    tx_hash8 = store_var_contract.functions.try_whether_equal(search_onchain_token).transact({
        "from": from_account,
        "gas": 3000000,
        "gasPrice": 0,
    })
    tx_receipt4 = w3.eth.waitForTransactionReceipt(tx_hash8)
    onchain_verify_gascost = onchain_verify_gascost + tx_receipt4.gasUsed
    result_verify = store_var_contract.functions.check_equal_or_not().call()
    end = datetime.datetime.now()
    # print('time cost of on chain verify: ', end - start)
    # print('result_verify', result_verify)
    print(onchain_verify_gascost)












#
# for i in range(1000):
#     # addfile_kw = kw
#     addfile_ID = str(np.random.randint(1000000, 1000000000000)).zfill(16)  # 生成添加文件ID
#     Kw_File_Use['chen'].append(addfile_ID)
# print("add file time", end1 - start1)

# for i in range(8000):
#     # addfile_kw = kw
#     addfile_ID = str(np.random.randint(1000000, 1000000000000)).zfill(16)  # 生成添加文件ID
#     Kw_File_Use['zhang'].append(addfile_ID)
# # print("add file time", end1 - start1)
# print("Kw_File_Use['zhang']",len(Kw_File_Use['zhang']))
#
# for i in range(8000):
#     # addfile_kw = kw
#     addfile_ID = str(np.random.randint(1000000, 1000000000000)).zfill(16)  # 生成添加文件ID
#     Kw_File_Use['zhang1'].append(addfile_ID)
# # print("add file time", end1 - start1)
# print("Kw_File_Use['zhang1']",len(Kw_File_Use['zhang1']))
#
# for i in range(8000):
#     # addfile_kw = kw
#     addfile_ID = str(np.random.randint(1000000, 1000000000000)).zfill(16)  # 生成添加文件ID
#     Kw_File_Use['chen1'].append(addfile_ID)
# # print("add file time", end1 - start1)
# print("Kw_File_Use['chen1']",len(Kw_File_Use['chen1']))
#

########################测试
#建立索引
start = datetime.datetime.now()
client_store_index, server_kw_index, server_ptr_file_nextptr, server_ptr_getfirstptr, chain_verify_index,timecost_onchain,timecost_client,timecost_server=Build_index(Kw_File_Use, file_to_file)
end=datetime.datetime.now()
t=end-start
# print('build total time cost',t)
# print('build index timecost_onchain',timecost_onchain)
# print('build index timecost client',timecost_client)
# print('build index timecost dualindex',timecost_server)




# ##############add file
# ceshikw_list1=kw_list[:1000]
# ceshikw_list2=kw_list[:2000]
# ceshikw_list3=kw_list[:4000]
# ceshikw_list4=kw_list[:8000]
# ceshikw_list5=kw_list[:15983]
# addfile_nonce = os.urandom(16)
# addfile_ID=str(np.random.randint(1000000000, 1000000000000)).zfill(16)
# sum_time_server=datetime.datetime.now()
# sum_time_chain=datetime.datetime.now()
# starty=sum_time_server
# for kw in ceshikw_list5:
#     client_store_index, server_kw_index, server_ptr_file_nextptr, server_ptr_getfirstptr, chain_verify_index,sum_time_server,sum_time_chain=add_file(kw, addfile_nonce, addfile_ID, client_store_index, server_kw_index, server_ptr_file_nextptr,server_ptr_getfirstptr, chain_verify_index,sum_time_server, sum_time_chain)
# print('time cost of addition--server', sum_time_server-starty)
# print('time cost of addition--chain', sum_time_chain-starty)


sum_time_chain=datetime.datetime.now()
sum_time_server=datetime.datetime.now()
ceshikw_list1=kw_list[:10]
starty=sum_time_server
for kw in ceshikw_list1:
    for j in range(1000):
        addfile_nonce = os.urandom(16)
        addfile_ID = str(np.random.randint(1000000000, 1000000000000)).zfill(16)
        client_store_index, server_kw_index, server_ptr_file_nextptr, server_ptr_getfirstptr, chain_verify_index,sum_time_server,sum_time_chain=add_file(kw, addfile_nonce, addfile_ID, client_store_index, server_kw_index, server_ptr_file_nextptr,server_ptr_getfirstptr, chain_verify_index,sum_time_server, sum_time_chain)







# ############delete***********************
# i=0
# start = datetime.datetime.now()
# for file in list_file_ID:
#     i=i+1
#     if i!=16:
#         server_kw_index = delete_file(file, server_ptr_getfirstptr, server_kw_index, server_ptr_file_nextptr)
# end = datetime.datetime.now()
# print('time of deleting file: ',end-start)







###########上传chain verify index 到blockchain


def ceshiget_verifyindex(number,chain_verify_index):
    ceshi_onchainverify_index={}
    i=0
    for kw in chain_verify_index:
        ceshi_onchainverify_index[kw]=chain_verify_index[kw]
        i=i+1
        if i==number:
            return ceshi_onchainverify_index

# ce1=ceshiget_verifyindex(1000,chain_verify_index)
# ce2=ceshiget_verifyindex(2000,chain_verify_index)
# ce3=ceshiget_verifyindex(4000,chain_verify_index)
# ce4=ceshiget_verifyindex(8000,chain_verify_index)
# ce5=ceshiget_verifyindex(15980,chain_verify_index)
# print('len(ceshiget_verifyindex)',len(ce1))
# print('len(ceshiget_verifyindex)',len(ce2))
# print('len(ceshiget_verifyindex)',len(ce3))
# print('len(ceshiget_verifyindex)',len(ce4))
# print('len(ceshiget_verifyindex)',len(ce5))




#####################将建立的索引分块加到blockchain
def upload_onchainindex_to_blockchain(chain_verify_index):
    gascost_upload=0
    start = datetime.datetime.now()
    batchtoken=[]
    batchhash=[]
    times=0
    batchint=int(len(chain_verify_index)/300)
    batchyue=len(chain_verify_index)%300
    int_times=0
    for token in chain_verify_index:
        times=times+1
        batchtoken.append(token)
        batchhash.append(chain_verify_index[token])
        if times==300 and int_times<batchint:
            int_times=int_times+1
            times=0
            tx_hash11=store_var_contract.functions.setbatch(batchtoken, batchhash,300).transact({
                "from": from_account,
                "gas": 90000000,
                "gasPrice": 0,
            })
            tx_receipt1 = w3.eth.waitForTransactionReceipt(tx_hash11)
            gascost_upload=gascost_upload+tx_receipt1.gasUsed
            batchtoken=[]
            batchhash=[]
        if int_times==batchint and times==batchyue:
            tx_hash12=store_var_contract.functions.setbatch(batchtoken, batchhash, batchyue).transact({
                "from": from_account,
                "gas": 90000000,
                "gasPrice": 0,
            })
            tx_receipt2 = w3.eth.waitForTransactionReceipt(tx_hash12)
            gascost_upload=gascost_upload+tx_receipt2.gasUsed
    end = datetime.datetime.now()
    print('gas cost of posting checklist to the blockchain', gascost_upload)
    print("time of posting checklist to the blockchain", end-start)

# upload_onchainindex_to_blockchain(ce1)
# upload_onchainindex_to_blockchain(ce2)
# upload_onchainindex_to_blockchain(ce3)
# upload_onchainindex_to_blockchain(ce4)
# upload_onchainindex_to_blockchain(ce5)

##############search###########################
list_searchresult_hashfid=[]
list_searchresult_fid=[]

# start = datetime.datetime.now()
# client_store_index, search_server_token, search_onchain_token,start_file_addr=owner_generate_search_token(client_store_index,"chen")
# list_searchresult_hashfid, list_searchresult_fid=server_search(search_server_token,search_onchain_token, server_kw_index, start_file_addr, list_searchresult_hashfid, list_searchresult_fid)
# list_searchresult_hashfid1=[]
# list_searchresult_fid1=[]
# client_store_index1, search_server_token1, search_onchain_token1,start_file_addr1=owner_generate_search_token(client_store_index,"zhang")
# list_searchresult_hashfid1, list_searchresult_fid1=server_search(search_server_token1,search_onchain_token1, server_kw_index, start_file_addr1, list_searchresult_hashfid1, list_searchresult_fid1)
#
# list_searchresult_hashfid2=[]
# list_searchresult_fid2=[]
# client_store_index2, search_server_token2, search_onchain_token2,start_file_addr2=owner_generate_search_token(client_store_index,"zhang1")
# list_searchresult_hashfid2, list_searchresult_fid2=server_search(search_server_token2,search_onchain_token2, server_kw_index, start_file_addr2, list_searchresult_hashfid2, list_searchresult_fid2)
#
# list_searchresult_hashfid3=[]
# list_searchresult_fid3=[]
# client_store_index3, search_server_token3, search_onchain_token3,start_file_addr3=owner_generate_search_token(client_store_index,"chen1")
# list_searchresult_hashfid3, list_searchresult_fid3=server_search(search_server_token3,search_onchain_token3, server_kw_index, start_file_addr3, list_searchresult_hashfid3, list_searchresult_fid3)
# end = datetime.datetime.now()
# print('local search timecost: ',end-start)
print(Kw_File_Use)
start = datetime.datetime.now()
for kw in ceshikw_list1:
    client_store_index, search_server_token, search_onchain_token,start_file_addr=owner_generate_search_token(client_store_index,kw)
    list_searchresult_hashfid, list_searchresult_fid=server_search(search_server_token,search_onchain_token, server_kw_index, start_file_addr, list_searchresult_hashfid, list_searchresult_fid)
    on_chain_search(list_searchresult_hashfid, search_onchain_token)
end = datetime.datetime.now()
print('local search timecost: ',end-start)







#
#
#
#
# on_chain_search(list_searchresult_hashfid,search_onchain_token)
# on_chain_search(list_searchresult_hashfid1,search_onchain_token1)
# on_chain_search(list_searchresult_hashfid2,search_onchain_token2)
# on_chain_search(list_searchresult_hashfid3,search_onchain_token3)

#######cai

