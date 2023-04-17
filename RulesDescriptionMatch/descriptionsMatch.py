# coding=utf-8

import re

def main():
    toml_path = r"""E:\BiLing\20220905-gitleaks-Docker\SecretDetection\bindata\default.toml"""
    reExp = re.compile(r'''description *?= *?"(.*?)"''')
    with open(toml_path, 'r', encoding='utf-8') as f:
        content = f.read()
        desList = reExp.findall(content)
        f.close()
    print(len(desList))
    print(desList)
    res = [] 
    for i in desList:
        if "--" in i:
            tmp_i = i.replace("--","\t")
            res.append(tmp_i)
    with open("desList.txt", 'w', encoding='utf-8') as f:
        for i in res:
            f.write(i)
            f.write('\n')
        f.close()



if __name__ == '__main__':
    main()