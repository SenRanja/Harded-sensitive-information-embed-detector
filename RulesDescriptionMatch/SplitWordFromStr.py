# encoding=utf-8

import yaml
import re

def upAndDownRate(secret: str):
    """传入字符串需要大于2\n升降序判断，公式 rate = InterruptNum/len(secret),初步可以认为0.16的阈值可以排除 升降序字符串导致的误报 """
    if len(secret) <= 2:
        raise Exception("str too short")

    charList = []
    UpOrDown: str = ""
    # UpOrDown是升降序的状态标志。此处认为向上为 "Up" ，向下为 "Down"，初始化为 ""
    InterruptNum = 0

    for singleChar in secret:
        charList.append(ord(singleChar))
    for index in range(len(charList)):
        if index==0:
            continue
        else:
            if charList[index] > charList[index-1]:
                    if UpOrDown=="Up":
                        pass
                    else:
                        UpOrDown = "Up"
                        InterruptNum += 1
            elif charList[index] < charList[index-1]:
                if UpOrDown=="Down":
                    pass
                else:
                    UpOrDown = "Down"
                    InterruptNum += 1
    return InterruptNum/len(secret)



def split2WordList(s: str):
    """传入字符串长度需要大于2
    该值返回一个比率，[0, 1]，趋近于1表示是人类识别字符串，趋近于0表示是随机字符串
    驼峰命名切割法: 将驼峰命名字符串切割为单个的字符串
    单词识别率计算方法：识别单词数量，进行匹配。识别到是英语单词的单词数量/单词数量，单词数量如果<=3则认为阈值过低，直接返回0."""
    if len(s) <= 2:
        raise Exception("str too short")

    if len(re.findall("\d", s))>=3:
        return 0

    wordListTotal = []
    wordListTotal.extend(re.findall(r"([A-Z][a-z]+|[a-z]+)(?=\b|\d|[A-Z\-_][a-zA-Z\-_]|[\-_\.])", s))
    wordListTotal.extend(re.findall(r"[A-Z]{2,}(?=\b|\d|[A-Z\-_][a-zA-Z\-_]|[\-_\.])", s))

    global WordBook
    wordList_len = len(wordListTotal)
    HumanbeingCanReadWordsNum = 0

    wordListTotal = [i.lower() for i in wordListTotal]

    for singleWord in wordListTotal:
        if len(singleWord)>=2 and singleWord in WordBook:
            # 直接匹配到直接识别
            HumanbeingCanReadWordsNum += 1
        else:
            if len(singleWord) >= 8:
                # 没有直接匹配到，对于长的字符进行去掉后缀匹配
                if singleWord[:-4] in WordBook:
                    HumanbeingCanReadWordsNum += 1
    try:
        rate = HumanbeingCanReadWordsNum/wordList_len
    except ZeroDivisionError as err:
        rate = 0
    finally:
        return rate


def main():
    with open("wordlist.yaml", 'r', encoding="utf-8") as f:
        yamlVar = yaml.safe_load(f)
        f.close()
    with open("wordList/american-english", 'r', encoding="utf-8") as f:
        global WordBook
        WordBook = f.read().lower()
        f.close()
    for i in yamlVar["secretList"]:
        targetVar = str(i)
        # if upAndDownRate(targetVar) > 0.4:
        #     if split2WordList(targetVar) < 0.34:
        #         print(targetVar)
        #         print(upAndDownRate(targetVar))
        #         print(split2WordList(targetVar))
        if upAndDownRate(targetVar) > 0:
            if split2WordList(targetVar) < 1:
                print(targetVar)
                print(upAndDownRate(targetVar))
                print(split2WordList(targetVar))

        # if upAndDownRate(targetVar) <= 0.4:
        #     print(targetVar)
        #     print("[upAndDownRate]", upAndDownRate(targetVar))
        # if upAndDownRate(targetVar) > 0.4:
        #     if split2WordList(targetVar) >= 0.3:
        #         print(targetVar)
        #         print("[wordIdentifier]", split2WordList(targetVar))

if __name__ == "__main__":
    main()

