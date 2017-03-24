from dict import getBinaryForDigit, getS1ValueFor, getS2ValueFor, getBinaryStringFor, prependZeroes, getModeName, getPropFromValue, getDictionaryDataFromBinary
import re
import datetime
import time

def checkValidDob(date):
	try:
		datetime.datetime.strptime(date, '%Y-%m-%d')
		return True
	except ValueError:
		return False

def askAction():
	action = prompt(
		message="Select the action:\n 1. Encryption\n 2. Decryption\n 3. Encrypt-Decrypt \nEnter the number against the action for selection",
		errormessage="Selection is mandatory. Value must be between 1 to 3",
		isvalid= lambda m: int(m) > 0 and int(m) < 4,
		isValidRegex= lambda m: re.match("^-?[0-9]$", m)
	)

	if(int(action) == 1):
		return 'E'
	elif(int(action) == 3):
		return 'B'
	elif(int(action) == 2):
		return 'D'

def askName():
	return prompt(
		message="Enter your name",
		errormessage="Name is mandatory. It must be less than or equal to 10 characters.\nAllowed: Only alphabets.",
		isvalid= lambda v: len(v) <= 10 and len(v) > 0,
		isValidRegex= lambda v: re.match("^[A-Za-z]*$", v))

def askStudentId():
	return prompt(
		message="Enter student ID",
		errormessage="Student ID must be a 10 digit.\nAllowed: Only numerals",
		isvalid= lambda s: len(s) == 10,
		isValidRegex= lambda s: re.match("^-?[0-9]+$", s))

def askDob():
	return prompt(
		message="Enter your date of birth (YYYY-MM-DD)",
		errormessage="Enter a valid date of birth\nAllowed Format: YYYY-MM-DD",
		isvalid = lambda s: checkValidDob(s),
		isValidRegex= lambda s: re.match("(\d{4})[/.-](\d{2})[/.-](\d{2})$", s))

def askRounds():
	return prompt(
		message="Enter total number of encryption rounds",
		errormessage="value must be a greater than zero.\nAllowed: Only numerals",
		isvalid= lambda s: int(s) > 0,
		isValidRegex= lambda s: re.match("^-?[0-9]+$", s))

def askMode(includeAll = True):
	quesAll = "Select the mode of operation:\n 1. DES 2. CBC 3. OFB 4. CTR 5. All\nEnter the number against the mode for selection"
	quesNoAll = "Select the mode of operation:\n 1. DES 2. CBC 3. OFB 4. CTR\nEnter the number against the mode for selection"
	msg = ''
	checkValue = 5
	if(includeAll):
		msg = quesAll
		checkValue = 6
	else:
		msg = quesNoAll

	return prompt(
		message= msg,
		errormessage="Selection is mandatory. Value must be between 1 to " + str(checkValue -1),
		isvalid= lambda m: int(m) > 0 and int(m) < checkValue,
		isValidRegex= lambda m: re.match("^-?[0-9]$", m)
	)

def askIv():
	return prompt(
		message="Enter Initialisation Vector (2 characters)",
		errormessage="IV is mandatory. \nAllowed: Only alphabets.",
		isvalid= lambda m: len(m) == 2,
		isValidRegex= lambda m: re.match("^[A-Za-z]*$", m))

def askEncryptedString(decryptOption = ''):
	ques = "Enter encrypted string"
	if(decryptOption != ''):
		ques += " for " + decryptOption
	return prompt(
			message= ques,
			errormessage="it is mandatory. \nAllowed: Only binary numbers (0/1).",
			isvalid= lambda m: len(m) > 0,
			isValidRegex= lambda m: re.match("^-?[0-1]+$", m))

def getInfo():
	name = askName()
	originalName = name
	nameLen = len(name)
	if(nameLen != 10):
		remainingDigits = (10 - nameLen)
		for x in range(0, remainingDigits):
			name = name + 'X'

	studentId = askStudentId()
	dob = askDob()
	totalRounds = askRounds()
	mode = askMode()

	iv = ''
	if(int(mode) > 1):
		iv = askIv()

	return {"name": name.upper(), "studentId": studentId, "totalRounds": totalRounds, "dob": dob, "mode": mode, "iv": iv, "originalName": originalName.upper()}

def getDecryptionInfo():
	dob = askDob()
	totalRounds = askRounds()
	encryptedString = ''
	mode = askMode()

	iv = ''
	if(int(mode) > 1):
		iv = askIv()

	# desEncData = ''
	# cbcEncData = ''
	# ofbEncData = ''
	# ctrEncData = ''
	# if(int(mode) == 5):
	# 	desEncData = askEncryptedString('DES')
	# 	cbcEncData = askEncryptedString('CBC')
	# 	ofbEncData = askEncryptedString('OFB')
	# 	ctrEncData = askEncryptedString('CTR')
	# else:
	# 	encryptedString = askEncryptedString()

	return {"dob": dob, "mode": mode, "totalRounds": totalRounds, "encData": encryptedString, "iv": iv }
	# "desEncData": desEncData, "cbcEncData": cbcEncData, "ofbEncData": ofbEncData, "ctrEncData": ctrEncData}

def getJulianDate(dateInstance):
	date = datetime.datetime.strptime(dateInstance, '%Y-%m-%d').date()
	return int(date.strftime('%j'))

def getNineBitKey(key):
	bDigit = getBinaryForDigit(key)
	# bDigit = '111000111'
	return prependZeroes(bDigit, 9)

def getBinaryDataForInput(info):
	plainText = info['name'] + ' ' + info['studentId'] + '.'
	binary = getBinaryStringFor(plainText)
	return binary

def encryptWithSelectedMode(key, binary, totalRounds, mode, iv):
	try:
		if(mode == 1):
			return encryptData(key, binary, totalRounds)
		elif(mode == 2):
			return encryptDataCbc(key, binary, totalRounds, iv)
		elif(mode == 3):
			return encryptDataOfb(key, binary, totalRounds, iv)
		elif(mode == 4):
			return encryptDataCtr(key, binary, totalRounds, iv)
		else:
			return {
				"des": encryptData(key, binary, totalRounds),
				"cbc": encryptDataCbc(key, binary, totalRounds, iv),
				"ofb": encryptDataOfb(key, binary, totalRounds, iv),
				"ctr": encryptDataCtr(key, binary, totalRounds, iv)
			}
	except Exception as e:
		print (e)
		return False

def generateTwelveBlockedData(binary):
	bStr = prependZeroes(binary, 12)
	binaryBlocks = [bStr[i:i+12] for i in range(0, len(bStr), 12)]
	return binaryBlocks

def encryptDataCbc(key, binary, totalRounds, iv):
	ivBinary = getBinaryStringFor(iv)
	binaryBlocks = generateTwelveBlockedData(binary)
	allBlockResult = ''

	for block in binaryBlocks:
		blockRes = generateDataForCbc(ivBinary, block, key, totalRounds)
		ivBinary = blockRes
		allBlockResult += blockRes
	return allBlockResult

def generateDataForCbc(ivBinary, binary, key, totalRounds):
	xorIvxPt = getBinaryForDigit(getXorValue(ivBinary, binary))
	xorIvxPt = prependZeroes(xorIvxPt, 12)
	blockCipherResult = encryptData(key, xorIvxPt, totalRounds)
	return blockCipherResult

def encryptDataOfb(key, binary, totalRounds, iv):
	ivBinary = getBinaryStringFor(iv)
	binaryBlocks = generateTwelveBlockedData(binary)
	allBlockResult = ''

	for block in binaryBlocks:
		blockRes = generateDataForOfb(ivBinary, block, key, totalRounds)
		ivBinary = blockRes['blockCipherResult']
		allBlockResult += blockRes['xorResult']
	return allBlockResult

def generateDataForOfb(ivBinary, binary, key, totalRounds):
	blockCipherResult = encryptData(key, ivBinary, totalRounds)
	xorBCrxPt = getBinaryForDigit(getXorValue(binary, blockCipherResult))
	xorBCrxPt = prependZeroes(xorBCrxPt, 12)
	return {"blockCipherResult": blockCipherResult, "xorResult": xorBCrxPt}

def encryptDataCtr(key, binary, totalRounds, iv):
	ivBinary = getBinaryStringFor(iv)
	binaryBlocks = generateTwelveBlockedData(binary)
	allBlockResult = ''

	for x in range(0, len(binaryBlocks)):
		counter = getBinaryForDigit(x)
		counter = prependZeroes(counter, 6)
		ctrInput = getBinaryForDigit(getXorValue(ivBinary, counter))
		blockRes = generateDataForCtr(ctrInput, binaryBlocks[x], key, totalRounds)
		print("block: " + str(binaryBlocks[x]) + " counter: " + str(counter) + " ctrNounce: " + str(ctrInput) + " ctrNoune#: " + str(getXorValue(ivBinary, counter)) + " res: " + str(blockRes))
		allBlockResult += blockRes
	return allBlockResult

def generateDataForCtr(nonceCounter, binary, key, totalRounds):
	blockCipherResult = encryptData(key, nonceCounter, totalRounds)
	xorBCrxPt = getBinaryForDigit(getXorValue(binary, blockCipherResult))
	xorBCrxPt = prependZeroes(xorBCrxPt, 12)
	return xorBCrxPt

def encryptData(key, binary, totalRounds):
	binaryBlocks = generateTwelveBlockedData(binary)
	allBlockResult = ''
	
	for block in binaryBlocks:
		l0 = block[:6]
		r0 = block[6:]
		blockRes = generateDataForBlock(0, totalRounds, key, l0, r0)
		allBlockResult += blockRes
	return allBlockResult

def generateDataForBlock(currRound, totalRounds, key, left, right):
	edKey = getRoundKey(currRound, key)
	expRight = right[0:2] + right[3] + right[2] + right[3] + right[2] + right[4:]
	xorKeyxRight = getBinaryForDigit(getXorValue(edKey, expRight))
	xorKeyxRight = prependZeroes(xorKeyxRight, 8)
	nr = getS1ValueFor(xorKeyxRight[:4]) + getS2ValueFor(xorKeyxRight[4:])
	nextRight = getBinaryForDigit(getXorValue(left, nr))
	nextRight = prependZeroes(nextRight, 6)

	if(currRound < totalRounds-1):
		return generateDataForBlock(currRound+1, totalRounds, key, right, nextRight)
	elif(currRound == totalRounds-1):
		return nextRight + right

def decryptWithSelectedMode(key, info):
	try:
		if(int(info['mode']) == 1):
			return decryptData(key, info['encData'], info['totalRounds'])
		elif(int(info['mode']) == 2):
			return decryptDataCbc(key, info['encData'], info['totalRounds'], info['iv'])
		elif(int(info['mode']) == 3):
			return decryptDataOfb(key, info['encData'], info['totalRounds'], info['iv'])
		elif(int(info['mode']) == 4):
			return decryptDataCtr(key, info['encData'], info['totalRounds'], info['iv'])
		else:
			return {
				"des": decryptData(key, info['desEncData'], info['totalRounds']),
				"cbc": decryptDataCbc(key, info['cbcEncData'], info['totalRounds'], info['iv']),
				"ofb": decryptDataOfb(key, info['ofbEncData'], info['totalRounds'], info['iv']),
				"ctr": decryptDataCtr(key, info['ctrEncData'], info['totalRounds'], info['iv'])
			}
	except Exception as e:
		print(e)
		return False

def decryptData(key, encData, totalRounds):
	binaryBlocks = generateTwelveBlockedData(encData)
	allBlockResult = ''

	for block in binaryBlocks:
		l0 = block[:6]
		r0 = block[6:]
		blockRes = decryptDataForBlock(int(totalRounds)-1, totalRounds, key, l0, r0)
		allBlockResult += blockRes
	
	inputString = getDictionaryDataFromBinary(allBlockResult)
	return {"allBlockResult": allBlockResult, "inputString": inputString}

def decryptDataForBlock(currRound, totalRounds, key, left, right):
	edKey = getRoundKey(currRound, key)
	expRight = right[0:2] + right[3] + right[2] + right[3] + right[2] + right[4:]
	xorKeyxRight = getBinaryForDigit(getXorValue(edKey, expRight))
	xorKeyxRight = prependZeroes(xorKeyxRight, 8)
	nr = getS1ValueFor(xorKeyxRight[:4]) + getS2ValueFor(xorKeyxRight[4:])
	nextRight = getBinaryForDigit(getXorValue(left, nr))
	nextRight = prependZeroes(nextRight, 6)
	newNextRight = prependZeroes(getBinaryForDigit(getXorValue(left, nextRight)), 6)

	if(currRound > 0):
		return decryptDataForBlock(currRound-1, totalRounds, key, right, nextRight)
	elif(currRound == 0):
		return nextRight + right

def decryptDataCbc(key, encData, totalRounds, iv):
	binaryBlocks = generateTwelveBlockedData(encData)
	ivBinary = getBinaryStringFor(iv)
	allBlockResult = ''

	for block in binaryBlocks:
		blockRes = decryptDataForCbc(key, block, totalRounds, ivBinary)
		allBlockResult += blockRes
		ivBinary = block

	inputString = getDictionaryDataFromBinary(allBlockResult)
	return {"allBlockResult": allBlockResult, "inputString": inputString}

def decryptDataForCbc(key, block, totalRounds, iv):
	l0 = block[:6]
	r0 = block[6:]
	cipherDecryptResult = decryptDataForBlock(int(totalRounds)-1, totalRounds, key, l0, r0)
	xoredResult = getBinaryForDigit(getXorValue(iv, cipherDecryptResult))
	xoredResult = prependZeroes(xoredResult, 12)
	return xoredResult

def decryptDataOfb(key, encData, totalRounds, iv):
	binaryBlocks = generateTwelveBlockedData(encData)
	ivBinary = getBinaryStringFor(iv)
	allBlockResult = ''

	for block in binaryBlocks:
		blockRes = decryptDataForOfb(ivBinary, key, block, totalRounds)
		allBlockResult += blockRes['allBlockResult']
		ivBinary = blockRes['encValue']
	inputString = getDictionaryDataFromBinary(allBlockResult)
	return {"allBlockResult": allBlockResult, "inputString": inputString}

def decryptDataForOfb(iv, key, block, totalRounds):
	blockCipherResult = encryptData(key, iv, int(totalRounds))
	xoredResult = getBinaryForDigit(getXorValue(blockCipherResult, block))
	xoredResult = prependZeroes(xoredResult, 12)
	return {"allBlockResult": xoredResult, "encValue": blockCipherResult}

def decryptDataCtr(key, encData, totalRounds, iv):
	allBlockResult = encryptDataCtr(key, encData, int(totalRounds), iv)
	inputString = getDictionaryDataFromBinary(allBlockResult)
	return {"allBlockResult": allBlockResult, "inputString": inputString}

def getXorValue(bnum1, bnum2):
	return int(bnum1, 2)^int(bnum2, 2)

def getRoundKey(round, key):
	roundKey = ''
	if(round < 2):
		roundKey = key[round: 8 + round]
	else:
		roundKey = key[round:] + key[0: (8 - len(key[round:]))]
	
	return roundKey

def printResult(output, info):
	print ("\n")
	print (bcolors.OKBLUE + ":: USER INFO ::" + bcolors.ENDC)
	print (bcolors.OKGREEN + "Name          : " + bcolors.ENDC + info['originalName'])
	print (bcolors.OKGREEN + "Student ID    : " + bcolors.ENDC + info['studentId'])
	print (bcolors.OKGREEN + "Date of Birth : " + bcolors.ENDC + info['dob'])
	print ('-----\n')
	print (bcolors.OKBLUE + ":: ENCRYPTION INFO ::" + bcolors.ENDC)
	print (bcolors.OKGREEN + "# Rounds : "  + bcolors.ENDC + info['totalRounds'])
	print (bcolors.OKGREEN + "Mode(s)  : " + bcolors.ENDC + getModeName(info['mode']))
	print ('-----\n')
	print (bcolors.OKBLUE + ":: RESULT ::" + bcolors.ENDC)
	if(int(info['mode']) == 5):
		print ("Result DES ----------------")
		print (bcolors.OKGREEN + 'Encrypted Value: ' + bcolors.ENDC + output['des']) 
		print (bcolors.OKGREEN + 'Human Readable : ' + bcolors.ENDC + " ".join(output['des'][i:i+6] for i in range(0, len(output['des']), 6)))
		print ("Result CBC ----------------")
		print (bcolors.OKGREEN + 'Encrypted Value: ' + bcolors.ENDC + output['cbc']) 
		print (bcolors.OKGREEN + 'Human Readable : ' + bcolors.ENDC + " ".join(output['cbc'][i:i+6] for i in range(0, len(output['cbc']), 6)))
		print ("Result OFB ----------------")
		print (bcolors.OKGREEN + 'Encrypted Value: ' + bcolors.ENDC + output['ofb']) 
		print (bcolors.OKGREEN + 'Human Readable : ' + bcolors.ENDC + " ".join(output['ofb'][i:i+6] for i in range(0, len(output['ofb']), 6)))
		print ("Result CTR ----------------")
		print (bcolors.OKGREEN + 'Encrypted Value: ' + bcolors.ENDC + output['ctr']) 
		print (bcolors.OKGREEN + 'Human Readable : ' + bcolors.ENDC + " ".join(output['ctr'][i:i+6] for i in range(0, len(output['ctr']), 6)))
	else:
		print (bcolors.OKGREEN + 'Encrypted Value: ' + bcolors.ENDC + output) 
		print (bcolors.OKGREEN + 'Human Readable : ' + bcolors.ENDC + " ".join(output[i:i+6] for i in range(0, len(output), 6)))

def printDecryptResult(output, info):
	print ("\n")
	print (bcolors.OKBLUE + ":: DECRYPTION INFO ::" + bcolors.ENDC)
	print (bcolors.OKGREEN + "# Rounds : "  + bcolors.ENDC + info['totalRounds'])
	print (bcolors.OKGREEN + "Mode(s)  : " + bcolors.ENDC + getModeName(info['mode']))
	print ('-----\n')
	print (bcolors.OKBLUE + ":: INPUT INFO ::" + bcolors.ENDC)
	print (bcolors.OKGREEN + "Input Data     : " + bcolors.ENDC + info['encData'])
	print (bcolors.OKGREEN + "Human Readable : " + bcolors.ENDC + " ".join(info['encData'][i:i+6] for i in range(0, len(info['encData']), 6)))
	print ('-----\n')
	print (bcolors.OKBLUE + ":: DECRYPTED USER INFO ::" + bcolors.ENDC)
	print (bcolors.OKGREEN + "Name          : " + bcolors.ENDC + output['inputString'].split()[0].replace("X", ""))
	print (bcolors.OKGREEN + "Student ID    : " + bcolors.ENDC + output['inputString'].split()[1].replace(".", ""))
	print (bcolors.OKGREEN + "Date of Birth : " + bcolors.ENDC + info['dob'])

def printEncryptDecryptResult(output, decryptionOutput, info):
	print ('-----\n')
	print (bcolors.OKBLUE + ":: MODE ::" + bcolors.ENDC)
	print (bcolors.OKGREEN + "# Rounds : "  + bcolors.ENDC + info['totalRounds'])
	print (bcolors.OKGREEN + "Mode(s)  : " + bcolors.ENDC + getModeName(info['mode']))
	print ('-----\n')
	print (bcolors.OKBLUE + ":: RESULT ::" + bcolors.ENDC)
	if(int(info['mode']) == 5):
		print ("Result DES Encryption ----------------")
		print (bcolors.OKGREEN + 'Encrypted Value: ' + bcolors.ENDC + output['des']) 
		print (bcolors.OKGREEN + 'Human Readable : ' + bcolors.ENDC + " ".join(output['des'][i:i+6] for i in range(0, len(output['des']), 6)))
		print ("Result DES Decryption ----------------")
		print (bcolors.OKGREEN + 'Name          : ' + bcolors.ENDC + decryptionOutput['des']['inputString'].split()[0].replace("X", ""))
		print (bcolors.OKGREEN + "Student ID    : " + bcolors.ENDC + decryptionOutput['des']['inputString'].split()[1].replace(".", ""))
		print (bcolors.OKGREEN + "Date of Birth : " + bcolors.ENDC + info['dob'])
		print ("Result CBC Encryption ----------------")
		print (bcolors.OKGREEN + 'Encrypted Value: ' + bcolors.ENDC + output['cbc']) 
		print (bcolors.OKGREEN + 'Human Readable : ' + bcolors.ENDC + " ".join(output['cbc'][i:i+6] for i in range(0, len(output['cbc']), 6)))
		print ("Result CBC Decryption ----------------")
		print (bcolors.OKGREEN + 'Name          : ' + bcolors.ENDC + decryptionOutput['cbc']['inputString'].split()[0].replace("X", ""))
		print (bcolors.OKGREEN + "Student ID    : " + bcolors.ENDC + decryptionOutput['cbc']['inputString'].split()[1].replace(".", ""))
		print (bcolors.OKGREEN + "Date of Birth : " + bcolors.ENDC + info['dob'])
		print ("Result OFB ----------------")
		print (bcolors.OKGREEN + 'Encrypted Value: ' + bcolors.ENDC + output['ofb']) 
		print (bcolors.OKGREEN + 'Human Readable : ' + bcolors.ENDC + " ".join(output['ofb'][i:i+6] for i in range(0, len(output['ofb']), 6)))
		print ("Result OFB Decryption ----------------")
		print (bcolors.OKGREEN + 'Name          : ' + bcolors.ENDC + decryptionOutput['ofb']['inputString'].split()[0].replace("X", ""))
		print (bcolors.OKGREEN + "Student ID    : " + bcolors.ENDC + decryptionOutput['ofb']['inputString'].split()[1].replace(".", ""))
		print (bcolors.OKGREEN + "Date of Birth : " + bcolors.ENDC + info['dob'])
		print ("Result CTR ----------------")
		print (bcolors.OKGREEN + 'Encrypted Value: ' + bcolors.ENDC + output['ctr']) 
		print (bcolors.OKGREEN + 'Human Readable : ' + bcolors.ENDC + " ".join(output['ctr'][i:i+6] for i in range(0, len(output['ctr']), 6)))
		print ("Result CTR Decryption ----------------")
		print (bcolors.OKGREEN + 'Name          : ' + bcolors.ENDC + decryptionOutput['ctr']['inputString'].split()[0].replace("X", ""))
		print (bcolors.OKGREEN + "Student ID    : " + bcolors.ENDC + decryptionOutput['ctr']['inputString'].split()[1].replace(".", ""))
		print (bcolors.OKGREEN + "Date of Birth : " + bcolors.ENDC + info['dob'])
	else:
		print ("Result Encryption ----------------")
		print (bcolors.OKGREEN + 'Encrypted Value: ' + bcolors.ENDC + output) 
		print (bcolors.OKGREEN + 'Human Readable : ' + bcolors.ENDC + " ".join(output[i:i+6] for i in range(0, len(output), 6)))
		print ("Result Decryption ----------------")
		print (bcolors.OKGREEN + 'Name          : ' + bcolors.ENDC + decryptionOutput['inputString'].split()[0].replace("X", ""))
		print (bcolors.OKGREEN + "Student ID    : " + bcolors.ENDC + decryptionOutput['inputString'].split()[1].replace(".", ""))
		print (bcolors.OKGREEN + "Date of Birth : " + bcolors.ENDC + info['dob'])

def prompt(message, errormessage, isvalid, isValidRegex):
    res = None
    while res is None:
        res = input(bcolors.OKGREEN + str(message)+': ' + bcolors.ENDC)
        if not isvalid(res) or not isValidRegex(res):
            print (bcolors.FAIL + str(errormessage) + bcolors.ENDC)
            res = None
    return res

class bcolors:
  HEADER = '\033[95m'
  OKBLUE = '\033[94m'
  OKGREEN = '\033[92m'
  WARNING = '\033[93m'
  FAIL = '\033[91m'
  ENDC = '\033[0m'
  BOLD = '\033[1m'
  UNDERLINE = '\033[4m'

try:
    input = raw_input
except NameError:
    pass