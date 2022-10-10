# coding=utf-8

import re

def main():
    toml_path = r"""E:\BiLing\20220905-gitleaks-Docker\GitleaksDir\config\gitleaks-n-all-kill.toml"""
    reExp = re.compile(r'''description ?= ?"(.*?)"''')
    with open(toml_path, 'r', encoding='utf-8') as f:
        content = f.read()
        desList = reExp.findall(content)
        f.close()
    print(len(desList))
    print(desList)
    with open("desList.txt", 'w', encoding='utf-8') as f:
        for i in desList:
            f.write(i)
            f.write('\n')
        f.close()



if __name__ == '__main__':
    main()