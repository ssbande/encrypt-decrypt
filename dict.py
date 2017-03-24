dictionary = {'A':1,'B':2,'C':3,'D':4,'E':5,'F':6,'G':7,'H':8,\
            'I':9,'J':10,'K':11,'L':12,'M':13,'N':14,'O':15,\
            'P':16,'Q':17,'R':18,'S':19,'T':20,'U':21,'V':22,\
            'W':23,'X':24,'Y':25,'Z':26,'0':27,'1':28,'2':29,\
            '3':30,'4':31 ,'5':32,'6':33,'7':34,'8':35,'9':36,\
            ' ':37,'.':38, '_':39}

S1={'0000':'101','0001':'010','0010':'001','0011':'110','0100':'011'\
    ,'0101':'100','0110':'111','0111':'000','1000':'001','1001':'100',\
    '1010':'110','1011':'010','1100':'000','1101':'111','1110':'101','1111':'011'}

S2={'0000':'100','0001':'000','0010':'110','0011':'101','0100':'111'\
    ,'0101':'001','0110':'011','0111':'010','1000':'101','1001':'011',\
    '1010':'000','1011':'111','1100':'110','1101':'010','1110':'001','1111':'100'}

MODES ={'1': 'DES', '2':'CBC', '3':'OFB', '4':'CTR', '5':'DES\nCBC\nOFB\nCTR'}

def getBinaryStringFor(s):
	bStr = ''
	for character in s:
		digit = dictionary[character.upper()]
		b = prependZeroes(getBinaryForDigit(digit), 6)
		bStr = bStr + b
	return bStr

def prependZeroes(bStr, num):
	x = len(bStr)
	if(x%num != 0):
		remainingDigits = (num - x%num)
		for x in range(0, remainingDigits):
			bStr = '0' + bStr
	return bStr

def getBinaryForDigit(digit):
	binary = ''
	if(digit == 0):
		binary = '0'

	while digit>0:
			binary+=str(digit%2)
			digit=digit//2
	return binary[::-1]

def getS1ValueFor(val):
	return S1[val]

def getS2ValueFor(val):
	return S2[val]

def getModeName(val):
	return MODES[val]

def getPropFromValue(val):
	# print('dict values for ' + str(val))
	# print(list(dictionary)[int(val) - 1])
	res = list(dictionary)[int(val) - 1 ]
	# print(dictionary.values().index(0))
	# res = dictionary.keys()[dictionary.values().index(int(val))]
	return res

def getDictionaryDataFromBinary(allBlockResult):
	bStr = prependZeroes(allBlockResult, 12)
	sixBlocks = [bStr[i:i+6] for i in range(0, len(bStr), 6)]

	inputString = ''
	for sblock in sixBlocks:
		inputString += getPropFromValue(int(sblock, 2))

	return inputString