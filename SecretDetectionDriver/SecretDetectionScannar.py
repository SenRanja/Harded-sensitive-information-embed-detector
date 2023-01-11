# encoding=utf-8
import os
import subprocess
import time
from multiprocessing import Pool, Manager

import yaml

import pandas as pd

def execTarget(q, entrophy, entrophyResultDir):
    while not q.empty():
        targetPath = q.get()
        print("任务开始", targetPath)
        resFileName = "{R}-{ENTROPHY}.csv".format(R=targetPath.split('\\')[-1], ENTROPHY=str(entrophy))
        commandExec = r"E:\BiLing\20220905-gitleaks-Docker\SecretDetection\SecretDetection.exe detect -s {S} -c C:\Users\ranja\Downloads\gitleaks-all-kill.toml -f csv -r {CSVFILENAME}".format(S=targetPath, CSVFILENAME=resFileName)
        scanSecretExec = subprocess.Popen(
            commandExec,
            # stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            shell=True,
            universal_newlines=True,
            cwd=entrophyResultDir,
        )
        try:
            scanSecretExec.wait(60*5)
            # outs, errs = scanSecretExec.communicate(timeout=2)
            # print(outs, errs)
        except Exception as err:
            print("[!]超时 "+str(err))
        finally:
            scanSecretExec.kill()

if __name__ == "__main__":
    # 读取配置
    GitPathsFile = "targetPaths.yaml"
    with open(GitPathsFile, 'r', encoding='utf-8') as f:
        targetPaths = yaml.safe_load(f)
        f.close()

    # 环境变量切一下
    r_dir = targetPaths['entrophyResultDir']
    os.chdir(r_dir)

    # 多进程跑数据
    manager = Manager()
    q = manager.Queue()
    for i in targetPaths['gitpaths']:
        q.put(i)

    pool_num = 3
    pool = Pool(pool_num)
    mp_list = []
    for i in range(pool_num):
        mp_list.append(pool.apply_async(execTarget, args=(q, int(targetPaths['entrophy']), targetPaths['entrophyResultDir'])))
    pool.close()
    pool.join()

    # csv数据合并
    csv2concatList = []
    for i in os.listdir():
        if i.endswith(".csv") and os.path.getsize(i)>0:
            csv2concatList.append(pd.read_csv(i))

    # 记录一下待会儿要清理的文件名
    toDeleteFileList = []
    for i in os.listdir():
        toDeleteFileList.append(i)

    df = pd.concat(csv2concatList, ignore_index=True,)
    df.to_csv(
        "{TIME}--entrophy-{E}.csv".format(TIME=time.strftime("%Y-%m-%d-%H-%M-%S", time.localtime()), E=str(targetPaths['entrophy'])),
        encoding='utf-8'
    )

    #删除过程文件
    for i in toDeleteFileList:
        os.remove(i)


