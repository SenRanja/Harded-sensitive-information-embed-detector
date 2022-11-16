# encoding=utf-8
import os
import subprocess
import time
from multiprocessing import Pool, Manager

import yaml

import pandas as pd

def execTarget(q, entrophy):
    while not q.empty():
        targetPath = q.get()
        resFileName = "{R}-{ENTROPHY}.csv".format(R=targetPath.split('\\')[-1], ENTROPHY=entrophy)
        commandExec = r"E:\BiLing\SecretDetection\SecretDetection.exe detect -s {S} -c C:\Users\ranja\Downloads\gitleaks-all-kill.toml -f csv -r {CSVFILENAME}".format(S=targetPath, CSVFILENAME=resFileName)
        scanSecretExec = subprocess.Popen(
            commandExec,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            shell=True,
            universal_newlines=True,
            cwd=r"C:\Users\ranja\Downloads\EntrophyTest\entrophyresult",
        )
        scanSecretExec.wait(60*4)
        outs, errs = scanSecretExec.communicate(timeout=2)
        scanSecretExec.kill()

if __name__ == "__main__":
    # 读取配置
    GitPathsFile = "targetPaths.yaml"
    with open(GitPathsFile, 'r', encoding='utf-8') as f:
        targetPaths = yaml.safe_load(f)
        f.close()

    # 环境变量切一下
    r_dir = r"C:\Users\ranja\Downloads\EntrophyTest\entrophyresult"
    os.chdir(r_dir)

    # 多进程跑数据
    manager = Manager()
    q = manager.Queue()
    for i in targetPaths['gitpaths']:
        q.put(i)

    pool_num = 8
    pool = Pool(pool_num)
    mp_list = []
    for i in range(pool_num):
        mp_list.append(pool.apply_async(execTarget, args=(q, int(targetPaths['entrophy']))))
    pool.close()
    pool.join()

    # csv数据合并
    csv2concatList = []
    for i in os.listdir():
        if i.endswith(".csv") and os.path.getsize(i)>0:
            csv2concatList.append(pd.read_csv(i))
    df = pd.concat(csv2concatList, ignore_index=True,)
    df.to_csv(
        "{TIME}--entrophy-{E}.csv".format(TIME=time.strftime("%Y-%m-%d-%H-%M-%S", time.localtime()), E=str(targetPaths['entrophy'])),
        encoding='utf-8'
    )

    #删除过程文件
    # for i in mp_list:
    #     os.remove(i)


